(ns bortexz.bybit.derivatives
  (:require [bortexz.resocket :as ws]
            [bortexz.utils.async :as ua]
            [buddy.core.codecs :as crypto.codecs]
            [buddy.core.mac :as crypto.mac]
            [clojure.core.async :as a]
            [clojure.set :as set]
            [hato.client :as http]
            [hato.middleware :as http-mw]
            [cognitect.anomalies :as err]
            [jsonista.core :as json])
  (:import [java.io IOException]
           [java.lang AutoCloseable]))

;; JSON

(def ^:private json-mapper
  (json/object-mapper
   {:encode-key-fn true
    :decode-key-fn true
    :bigdecimals   true}))

(defn- ->json
  [o]
  (json/write-value-as-string o json-mapper))

(defn- <-json
  [o]
  (json/read-value o json-mapper))

;; Auth SIGN

(defn- sign
  [to-sign key-secret]
  (-> (crypto.mac/hash to-sign {:key key-secret :alg :hmac+sha256})
      (crypto.codecs/bytes->hex)))

;; REST Private

(defn- prepare-auth-request
  [{:keys [params request-method] :as req} {:keys [api-key recv-window api-secret]}]
  (let [params-str (cond
                     (and (seq params) (= :get request-method))
                     (http-mw/generate-query-string params)

                     (and (seq params) (= :post request-method))
                     (->json params)

                     :else
                     "")

        millis     (System/currentTimeMillis)
        to-sign    (str millis api-key (when recv-window recv-window) params-str)
        signed     (sign to-sign api-secret)
        new-hs     (cond->       {"X-BAPI-SIGN-TYPE" "2"
                                  "X-BAPI-SIGN" signed
                                  "X-BAPI-API-KEY" api-key
                                  "X-BAPI-TIMESTAMP" (str millis)}

                     recv-window (assoc "X-BAPI-RECV-WINDOW" (str recv-window)))

        req        (update req :headers merge new-hs)]
    (if (= :get request-method)
      (assoc req :query-string params-str)
      (assoc req :body params-str))))

(defn- prepare-public-request
  [{:keys [params] :as req}]
  (cond-> req
    (seq params) (assoc :query-string (http-mw/generate-query-string params))))

(def ^:private rest-endpoints
  {:testnet "api-testnet.bybit.com"
   :bybit "api.bybit.com"
   :bytick "api.bytick.com"})

;; Public rest-client

(defn rest-client
  "Creates a rest client. See [[request]].
  
   opts:
   - `auth` mandatory to use auth? requests. 
     map of:
     - `api-key` 
     - `api-secret`
     - `recv-window` (optional) defaults to 3 seconds.
   
   - `environment` e/o #{:testnet :bybit :bytick}
   
   - `http-opts` map of:
     - `connect-timeout` defaults to 10 secs
     - `response-timeout`"
  [{:keys [auth http-opts environment] :as _client}]
  (let [http-opts     (merge {:connect-timeout 10000} http-opts)
        auth          (when auth (merge {:recv-window 3000} auth))
        base-endpoint (rest-endpoints environment)
        conn-timeout  (:connect-timeout http-opts)
        http-client   (http/build-http-client
                       (cond-> {}
                         conn-timeout (assoc :connect-timeout conn-timeout)))]
    (merge _client
           {:base-endpoint base-endpoint
            :http-client   http-client}
           (when auth {:auth auth}))))

(defn request
  "HTTP Request using client and args:
   - `method` :get, :post, ...
   - `uri` i.e `/derivatives/v3/public/tickers`
   - `params` map of parameters
   - `auth?` if request should use authentication

   Returns the body of the response, json parsed, when status is 200. On exceptional HTTP codes or client exceptions,
   throws ExceptionInfo containing key `:cognitect.anomalies/category`, as well as `args` used, plus
   `status` and `body` if exception due to exceptional http code. Short circuits an auth? request with 
   :cognitect.anomalies/forbidden when auth? is true but api-key or api-secret are not specified on the client."
  [{:keys [http-client base-endpoint auth http-opts] :as _client}
   {:keys [method uri auth? params] :as args}]
  (let [{:keys [response-timeout]} http-opts
        req (cond-> {:http-client    http-client
                     :scheme         :https
                     :server-name    base-endpoint
                     :headers        {"Content-Type" "application/json"}
                     :uri            uri
                     :params         params
                     :request-method method}
              response-timeout (assoc :timeout response-timeout))

        req (if auth?
              (if (and (:api-key auth) (:api-secret auth)) 
                (prepare-auth-request req auth)
                (throw
                 (ex-info "Auth key/secret not specified in auth request"
                          {::err/category ::err/forbidden
                           :args args})))
              (prepare-public-request req))]
    (try
      (let [res    (http/request* req)
            status (:status res)
            ok?    (http-mw/unexceptional-status? status)
            body   (cond-> (:body res) ok? <-json)]
        (if ok?
          body
          (throw
           (ex-info (format "HTTP Error status %s" status)
                    {:status status
                     :body body
                     :args args
                     ::err/category (case status
                                      403 ::err/forbidden
                                      404 ::err/not-found
                                      ::err/fault)}))))
      (catch Exception e
        (throw
         (ex-info "Client exception"
                  {:args args
                   ::err/category (cond
                                    (instance? IOException e) ::err/unavailable
                                    :else ::err/fault)}))))))

(comment
  (def c (rest-client {:environment :bybit}))
  (request c {:method :get
              :uri "/derivatives/v3/public/tickers"
              :params {:category "linear"
                       :symbol "BTCUSDT"}}))

;; Private Websocket API

(defn- ws-auth-query-string
  [{:keys [api-key api-secret expire-millis]}]
  (let [expires (+ (System/currentTimeMillis) expire-millis)
        to-sign (format "GET/realtime%d" expires)
        signed  (sign to-sign api-secret)]
    (format "api_key=%s&expires=%d&signature=%s" api-key expires signed)))

(def ^:private ws-env->endpoint
  {:mainnet "wss://stream.bybit.com/"
   :testnet "wss://stream-testnet.bybit.com/"})

(def ^:private ws-channel->uri
  {:usdt-contract    "contract/usdt/public/v3"
   :usdc-contract    "contract/usdc/public/v3"
   :usdc-option      "option/usdc/public/v3"
   :inverse-contract "contract/inverse/public/v3"
   :contract-account "contract/private/v3"
   :unified-account  "unified/private/v3"})

(def ^:private ws-auth-channels
  #{:contract-account :unified-account})

(defn- ws-state
  []
  {:conn      nil ; Current resocket connection
   :requests  {}  ; Inflight requests, map of uuid to set of topics being sub/unsub
   :subs      #{} ; Currently subscribed ws topics
   :topics    #{} ; Currently subscribed user topics
   :messages  []  ; Pending messages to send to sync subs
   })

(defn- update-ws-subs
  [state sub unsub]
  (let [{:keys [requests subs topics conn] :as state}
        (cond-> state
          true        (update :messages empty)
          (seq sub)   (update :topics   set/union      sub)
          (seq unsub) (update :topics   set/difference unsub))]
    (if (some? conn)
      (let [ws-sub    (set/difference topics (set/union (set (mapcat val requests)) subs))
            ws-unsub  (set/difference subs   topics)
            sub-req   (when (seq ws-sub)
                        {:op     "subscribe"
                         :args   (vec ws-sub)
                         :req_id (str (random-uuid))})
            unsub-req (when (seq ws-unsub)
                        {:op     "unsubscribe"
                         :args   (vec ws-unsub)
                         :req_id (str (random-uuid))})]
        (cond-> state
          sub-req   (-> (update :messages conj sub-req)
                        (update :requests assoc (:req_id sub-req) sub-req))
          unsub-req (-> (update :messages conj unsub-req)
                        (update :requests assoc (:req_id unsub-req) unsub-req))))
      state)))

(defn- on-ws-response
  [state msg]
  (let [ok?    (:success msg)
        req-id (:req_id msg)
        req    (get-in state [:requests req-id])
        op     (:op req)
        args   (set (:args req))]
    (cond-> (update state :requests dissoc req-id)
      (and ok?       (#{"subscribe"}   op)) (update :subs   set/union      args)
      (and ok?       (#{"unsubscribe"} op)) (update :subs   set/difference args)
      (and (not ok?) (#{"subscribe"}   op)) (update :topics set/difference args)
      true                                  (update-ws-subs nil nil))))

;; Websocket Client

(defrecord WebsocketClient [auth
                            environment
                            pub-opts
                            errors-ch
                            ws-opts
                            reconnector-opts
                            data-pub
                            state_
                            close-ch
                            subs-process
                            ws-process]

  AutoCloseable
  (close [_]
    (when close-ch     (a/put! close-ch true))
    (when subs-process (a/<!! subs-process))
    (when ws-process   (a/<!! ws-process)))

  a/Pub
  (sub* [_ t ch close?] (a/sub* data-pub t ch close?))
  (unsub* [_ t ch] (a/unsub* data-pub t ch))
  (unsub-all* [_] (a/unsub-all* data-pub))
  (unsub-all* [_ t] (a/unsub-all* data-pub t)))

(defn websocket-client
  "Creates a websocket client.
   
   opts:
   
   - `auth` only required when using an authenticated endpoint. Map of:
     - `api-key`
     - `api-secret`
     - `expire-millis` (optional) defaults to 3secs.
   
   - `channel` either of:
     #{:usdt-contract 
       :usdc-contract 
       :usdc-option 
       :inverse-contract
       :contract-account 
       :unified-account}
   
   - `environment` either of: 
     #{:mainnet :testnet}

   - `pub-opts` (optional) options related to the internal pub used to dispatch messages. map of:
     - `data-buf` (optional) buffer for data source ch
     - `topic-buf-fn` (optional) buf-fn to use when creating internal pub. Defaults to `(constantly 32)`
   
   - `errors-ch` (optional) channel that contains request errors, for troubleshoting subscriptions.
   
   - `ws-opts` (optional) websocket connection options used in the resocket/reconnector. 
     map of (all optional):
     - `input-buf`
     - `output-buf`
     - `ping-interval` 20 secs by default
     - `ping-timeout`
     - `connect-timeout`
     - `close-timeout`
     - `ex-handler`
   
   - reconnector-opts (optional) options for resocket/reconnector. map of:
     - `retry-ms-fn`
     - `on-error-retry-fn?`
   
   Returns a websocket client that implements a/Pub protocol, and handles reconnections automatically through 
   resocket/reconnector. You can subscribe to topics as if it were a core.async pub, and the client will internally
   handle subscriptions. i.e `(a/sub ws-client 'orderbook.50.BTCUSDT' (a/chan) close?)`"
  [{:keys [auth environment channel errors-ch pub-opts ws-opts reconnector-opts]}]
  (let [auth? (ws-auth-channels channel)
        _ (when (and auth? (not (and (:api-key auth) (:api-secret auth))))
            (throw (ex-info "api-key/secret not specified to auth endpoint"
                            {::err/category ::err/forbidden
                             :environment environment})))
        auth (when auth? (merge {:expire-millis 3000} auth))
        pub-opts (merge {:topic-buf-fn (constantly 32)} pub-opts)
        ws-opts (merge {:ping-interval 20000} ws-opts)

        recon-opts (merge
                    reconnector-opts
                    {:get-url (fn []
                                (cond-> (str (ws-env->endpoint environment) (ws-channel->uri channel))
                                  auth (str "?" (ws-auth-query-string auth))))
                     :get-opts (fn []
                                 (merge ws-opts {:input-parser <-json
                                                 :output-parser ->json}))})

        data-ch    (a/chan (:data-buf pub-opts))
        events-ch  (a/chan)
        control-ch (a/chan 16)
        subs-ch    (a/merge [events-ch control-ch])

        data-pub (ua/pub data-ch :topic {:buf-fn (:topic-buf-fn pub-opts) :events-ch events-ch})

        {:keys [connections close]} (ws/reconnector recon-opts)

        state_ (atom (ws-state))

        subs-process
        (a/go-loop []
          (when-let [v (a/<! subs-ch)]
            (let [[type data] v
                  {:keys [conn messages]}
                  (swap!
                   state_
                   (fn [state]
                     (case type
                       :on-fill     (update-ws-subs state #{data} nil)
                       :on-empty    (update-ws-subs state nil #{data})
                       :on-connect  (-> state
                                        (assoc :conn data)
                                        (update-ws-subs nil nil))
                       :on-close    (-> state
                                        (assoc  :conn      nil)
                                        (update :subs      empty)
                                        (update :requests  empty)
                                        (update :messages  empty))
                       :on-response (on-ws-response state data))))]
              (when (:output conn)
                (a/<! (a/onto-chan! (:output conn) messages false)))
              (when (and (#{:on-response} type) (not (:success data)) errors-ch)
                (a/>! errors-ch {:message data}))
              (recur))))

        ws-process
        (a/go-loop []
          (if-let [conn (a/<! connections)]
            (do
              (a/>! control-ch [:on-connect conn])
              (let [input (:input conn)]
                (loop []
                  (when-let [v (a/<! input)]
                    (cond
                      (:topic v)   (a/>! data-ch v)
                      (:req_id v)  (a/>! control-ch [:on-response v]))
                    (recur))))
              (a/>! control-ch [:on-close])
              (recur))
            (do (a/close! control-ch) (a/close! data-ch))))]
      (map->WebsocketClient
       {:auth auth
        :environment environment
        :pub-opts pub-opts
        :errors-ch errors-ch
        :ws-opts ws-opts
        :reconnector-opts reconnector-opts
        :data-pub data-pub
        :close-ch close
        :state_ state_
        :ws-process ws-process
        :subs-process subs-process})))

(comment
  (def c (websocket-client {:environment :mainnet 
                            :channel :usdt-contract}))
  
  (def ch (a/chan))
  (ua/consume ch (fn [m] (println m)))
  
  (a/sub c "publicTrade.BTCUSDT" ch)
  (a/unsub c "publicTrade.BTCUSDT" ch)
  
  (.close c))
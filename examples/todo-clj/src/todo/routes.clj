(ns todo.routes
  (:require [todo.db :as db]
            [cheshire.core :as json]
            [reitit.ring :as ring]
            [ring.util.response :as resp]
            [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
            [todo.specs :as specs]))

(defn- json-response
  "Return a Ring response with JSON body. No security headers (epoch 0)."
  ([body]
   (json-response 200 body))
  ([status body]
   {:status  status
    :headers {"Content-Type" "application/json"}
    :body    (json/generate-string body)}))

(s/fdef json-response
  :args (s/alt :body (s/cat :body ::specs/json-body)
               :status+body (s/cat :status :todo.response/status :body ::specs/json-body))
  :ret ::specs/json-response
  ;; status defaults to 200, and the body round-trips through JSON
  :fn (fn [{[arity {:keys [status body]}] :args ret :ret}]
        (and (= (if (= arity :body) 200 status) (:status ret))
             (= body (json/parse-string (:body ret) true)))))

(defn- parse-json-body
  "Read and parse JSON from the request body."
  [request]
  (when-let [body (:body request)]
    (json/parse-stream (io/reader body) true)))

(defn- parse-id
  "Extract :id path parameter as a long."
  [request]
  (some-> (get-in request [:path-params :id])
          parse-long))

(s/fdef parse-id
  :args (s/cat :request ::specs/request)
  :ret (s/nilable int?)
  ;; ret is the number the :id segment denotes; nil when the segment is
  ;; missing, isn't a decimal integer, or is out of long range
  :fn (fn [{{:keys [request]} :args ret :ret}]
        (let [id (get-in request [:path-params :id])]
          (if (some? ret)
            (= (bigint id) ret)
            (or (nil? id)
                (nil? (re-matches #"[+-]?\d+" id))
                (not (<= Long/MIN_VALUE (bigint id) Long/MAX_VALUE)))))))

;; --- Handlers ---

(defn list-todos [_request]
  (json-response (db/list-todos)))

(s/fdef list-todos
  :args (s/cat :request ::specs/request)
  :ret (specs/response-with-status 200))

(defn create-todo [request]
  (let [body (parse-json-body request)]
    (if-let [title (:title body)]
      (let [todo (db/create-todo! {:title title :done (get body :done 0)})]
        (json-response 201 todo))
      (json-response 400 {:error "title is required"}))))

(s/fdef create-todo
  :args (s/cat :request ::specs/request)
  :ret (specs/response-with-status 201 400))

(defn get-todo [request]
  (if-let [todo (db/get-todo (parse-id request))]
    (json-response todo)
    (json-response 404 {:error "not found"})))

(s/fdef get-todo
  :args (s/cat :request ::specs/request)
  :ret (specs/response-with-status 200 404))

(defn update-todo [request]
  (let [id   (parse-id request)
        body (parse-json-body request)]
    (if (and id (:title body))
      (if-let [todo (db/update-todo! id body)]
        (json-response todo)
        (json-response 404 {:error "not found"}))
      (json-response 400 {:error "title is required"}))))

(s/fdef update-todo
  :args (s/cat :request ::specs/request)
  :ret (specs/response-with-status 200 400 404))

(defn delete-todo [request]
  (let [id (parse-id request)]
    (if (db/delete-todo! id)
      (json-response {:deleted id})
      (json-response 404 {:error "not found"}))))

(s/fdef delete-todo
  :args (s/cat :request ::specs/request)
  :ret (specs/response-with-status 200 404))

(defn index-page [_request]
  (if-let [resource (io/resource "public/index.html")]
    {:status  200
     :headers {"Content-Type" "text/html"}
     :body    (slurp resource)}
    {:status 404 :body "index.html not found"}))

(s/fdef index-page
  :args (s/cat :request ::specs/request)
  :ret (specs/response-with-status 200 404))

;; --- Router ---

(def app
  (ring/ring-handler
   (ring/router
    [["/" {:get {:handler index-page}}]
     ["/api/todos"
      {:get  {:handler list-todos}
       :post {:handler create-todo}}]
     ["/api/todos/:id"
      {:get    {:handler get-todo}
       :put    {:handler update-todo}
       :delete {:handler delete-todo}}]])))

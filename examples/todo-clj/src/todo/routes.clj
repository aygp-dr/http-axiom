(ns todo.routes
  (:require [todo.db :as db]
            [cheshire.core :as json]
            [reitit.ring :as ring]
            [ring.util.response :as resp]
            [clojure.java.io :as io]))

(defn- json-response
  "Return a Ring response with JSON body. No security headers (epoch 0)."
  ([body]
   (json-response 200 body))
  ([status body]
   {:status  status
    :headers {"Content-Type" "application/json"}
    :body    (json/generate-string body)}))

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

;; --- Handlers ---

(defn list-todos [_request]
  (json-response (db/list-todos)))

(defn create-todo [request]
  (let [body (parse-json-body request)]
    (if-let [title (:title body)]
      (let [todo (db/create-todo! {:title title :done (get body :done 0)})]
        (json-response 201 todo))
      (json-response 400 {:error "title is required"}))))

(defn get-todo [request]
  (if-let [todo (db/get-todo (parse-id request))]
    (json-response todo)
    (json-response 404 {:error "not found"})))

(defn update-todo [request]
  (let [id   (parse-id request)
        body (parse-json-body request)]
    (if (and id (:title body))
      (if-let [todo (db/update-todo! id body)]
        (json-response todo)
        (json-response 404 {:error "not found"}))
      (json-response 400 {:error "title is required"}))))

(defn delete-todo [request]
  (let [id (parse-id request)]
    (if (db/delete-todo! id)
      (json-response {:deleted id})
      (json-response 404 {:error "not found"}))))

(defn index-page [_request]
  (if-let [resource (io/resource "public/index.html")]
    {:status  200
     :headers {"Content-Type" "text/html"}
     :body    (slurp resource)}
    {:status 404 :body "index.html not found"}))

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

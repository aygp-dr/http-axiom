(ns todo.routes-test
  "Route and handler tests with plain Ring request maps: no server, no network."
  (:require [cheshire.core :as json]
            [clojure.spec.alpha :as s]
            [clojure.spec.test.alpha :as stest]
            [clojure.string :as str]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [todo.middleware :as mw]
            [todo.routes :as routes]
            [todo.specs :as specs]
            [todo.test-db :refer [with-temp-db]])
  (:import (java.io ByteArrayInputStream)))

;; Exercise every s/fdef :args spec while the unit tests run.
(use-fixtures :once
  (fn [f] (stest/instrument) (try (f) (finally (stest/unstrument)))))

(use-fixtures :each with-temp-db)

(defn- request
  "A Ring request map as ring-mock would build it, with an optional JSON body."
  ([method uri] (request method uri nil))
  ([method uri body]
   (cond-> {:request-method method :uri uri :headers {}}
     (some? body)
     (assoc :headers {"content-type" "application/json"}
            :body (ByteArrayInputStream. (.getBytes ^String (json/generate-string body) "UTF-8"))))))

;; What todo.main serves.
(def ^:private app (mw/wrap-epoch-0 routes/app))

(defn- json-body [resp] (json/parse-string (:body resp) true))

(defn- check-ret
  "Assert that `resp` conforms to the :ret spec of handler `sym`; return it."
  [sym resp]
  (let [spec (:ret (s/get-spec sym))]
    (is (s/valid? spec resp) (s/explain-str spec resp))
    resp))

(deftest index-page-serves-the-spa-shell
  (let [resp (check-ret `routes/index-page (app (request :get "/")))]
    (is (= 200 (:status resp)))
    (is (= "text/html" (get-in resp [:headers "Content-Type"])))
    (is (str/includes? (:body resp) "<title>todo-clj epoch 0</title>"))))

(deftest todo-crud-lifecycle
  (is (= [] (json-body (check-ret `routes/list-todos (app (request :get "/api/todos"))))))
  (let [created (check-ret `routes/create-todo (app (request :post "/api/todos" {:title "Buy milk"})))
        todo    (json-body created)
        path    (str "/api/todos/" (:id todo))]
    (is (= 201 (:status created)))
    (is (s/valid? ::specs/todo todo))
    (is (= {:title "Buy milk" :done 0} (dissoc todo :id)))
    (testing "read"
      (is (= todo (json-body (check-ret `routes/get-todo (app (request :get path))))))
      (is (= [todo] (json-body (app (request :get "/api/todos"))))))
    (testing "replace, as index.html's toggle button does"
      (let [resp (check-ret `routes/update-todo (app (request :put path {:title "Buy milk" :done 1})))]
        (is (= 200 (:status resp)))
        (is (= (assoc todo :done 1) (json-body resp)))))
    (testing "delete"
      (let [resp (check-ret `routes/delete-todo (app (request :delete path)))]
        (is (= 200 (:status resp)))
        (is (= {:deleted (:id todo)} (json-body resp))))
      (is (= 404 (:status (app (request :get path)))))
      (is (= 404 (:status (app (request :delete path))))))))

(deftest invalid-requests
  (testing "a todo needs a title"
    (let [resp (check-ret `routes/create-todo (app (request :post "/api/todos" {:done 1})))]
      (is (= 400 (:status resp)))
      (is (= {:error "title is required"} (json-body resp))))
    (is (= 400 (:status (check-ret `routes/update-todo (app (request :put "/api/todos/1" {:done 1})))))))
  (testing "unknown and non-numeric ids are 404"
    (let [resp (check-ret `routes/get-todo (app (request :get "/api/todos/999")))]
      (is (= 404 (:status resp)))
      (is (= {:error "not found"} (json-body resp))))
    (is (= 404 (:status (app (request :get "/api/todos/abc")))))
    (is (= 404 (:status (check-ret `routes/update-todo (app (request :put "/api/todos/999" {:title "x"}))))))
    (is (= 404 (:status (check-ret `routes/delete-todo (app (request :delete "/api/todos/abc"))))))))

(deftest epoch-0-sends-no-security-headers
  ;; spec.org A2.3: at epoch 0 every security header is absent, on success
  ;; and error responses alike. hax scenario S-001 expects exactly this.
  (doseq [resp [(app (request :get "/"))
                (app (request :get "/api/todos"))
                (app (request :get "/api/todos/999"))
                (app (request :post "/api/todos" {}))]]
    (is (= #{"Content-Type"} (set (keys (:headers resp)))))))

(deftest handlers-called-directly
  ;; routes/app holds the handler fns themselves, not their vars, so calling
  ;; the handlers directly is what puts their :args specs under instrumentation.
  (let [todo (json-body (routes/create-todo (request :post "/api/todos" {:title "Rotate JWT key"})))
        req  (fn [method & [body]]
               (assoc (request method (str "/api/todos/" (:id todo)) body)
                      :path-params {:id (str (:id todo))}))]
    (is (= todo (json-body (routes/get-todo (req :get)))))
    (is (= [todo] (json-body (routes/list-todos (request :get "/api/todos")))))
    (is (= 200 (:status (routes/update-todo (req :put {:title "Rotate JWT key" :done 1})))))
    (is (= 200 (:status (routes/delete-todo (req :delete)))))
    (is (= 200 (:status (routes/index-page (request :get "/")))))))

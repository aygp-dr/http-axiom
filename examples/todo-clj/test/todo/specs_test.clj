(ns todo.specs-test
  "Generative checks for every pure s/fdef'd fn, plus data-spec sanity.
  Per https://clojure.org/guides/spec (Testing)."
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.test.alpha :as stest]
            [clojure.test :refer [deftest is testing]]
            [todo.db]
            [todo.main]
            [todo.middleware]
            [todo.routes :as routes]
            [todo.specs :as specs]))

(def ^:private check-opts {:clojure.spec.test.check/opts {:num-tests 50}})

;; Side-effecting fns: fdef'd for instrumentation, never generatively checked
;; here. The todo.db fns, and the handlers that call them, read and write
;; SQLite (db_test checks the db fdefs against a throwaway database).
;; index-page reads a classpath resource; -main starts Jetty.
(def ^:private side-effecting
  #{`todo.db/init-db! `todo.db/list-todos `todo.db/get-todo `todo.db/create-todo!
    `todo.db/update-todo! `todo.db/delete-todo!
    `routes/list-todos `routes/create-todo `routes/get-todo `routes/update-todo
    `routes/delete-todo `routes/index-page
    `todo.main/-main})

(defn- checkable []
  (remove side-effecting
          (mapcat stest/enumerate-namespace '[todo.db todo.routes todo.middleware todo.main])))

(deftest fdefs-hold-under-generative-testing
  (let [results (stest/check (checkable) check-opts)]
    (is (= #{`routes/json-response `routes/parse-id `todo.middleware/wrap-epoch-0}
           (set (map :sym results))))
    (doseq [r results]
      (testing (str (:sym r))
        (is (nil? (:failure r))
            (pr-str (stest/abbrev-result r)))))))

(deftest data-specs-generate-and-conform
  (doseq [k [::specs/todo ::specs/todos ::specs/id-arg ::specs/todo-input ::specs/request
             ::specs/response ::specs/json-response ::specs/handler ::specs/json-body]]
    (testing (str k)
      (is (every? (fn [[v _]] (s/valid? k v)) (s/exercise k 10))))))

(deftest real-values-conform
  (testing "the request bodies index.html sends"
    (is (s/valid? ::specs/todo-input {:title "Buy milk"}))
    (is (s/valid? ::specs/todo-input {:title "Buy milk" :done 1})))
  (testing "the spec.org A1.3 error shape (the epoch-0 app sends only :error)"
    (is (s/valid? ::specs/error-body {:error "not-found" :message "Todo 42 does not exist" :status 404})))
  (testing "a real response"
    (is (s/valid? ::specs/response (routes/index-page {:request-method :get :uri "/"})))))

(ns todo.specs
  "Data specs for the todo-clj service (https://clojure.org/guides/spec).
  Function specs (s/fdef) live next to each defn in todo.db, todo.routes,
  todo.middleware and todo.main.

  Generators are built lazily (inside fns), so loading this ns never needs
  test.check: `clojure -M:run` doesn't have it."
  (:require [cheshire.core :as json]
            [clojure.spec.alpha :as s]
            [clojure.spec.gen.alpha :as gen]
            [clojure.string :as str]))

;; --- Todo entity: a row of the todos table, as the API returns it ---
;;   id    INTEGER PRIMARY KEY AUTOINCREMENT
;;   title TEXT    NOT NULL
;;   done  INTEGER NOT NULL DEFAULT 0   (index.html toggles it between 0 and 1)

(s/def :todo.todo/id pos-int?)
(s/def :todo.todo/title string?)
(s/def :todo.todo/done #{0 1})
(s/def ::todo (s/keys :req-un [:todo.todo/id :todo.todo/title :todo.todo/done]))
(s/def ::todos (s/coll-of ::todo :kind sequential? :gen-max 5))

;; An id as it reaches the db fns: parsed from the URL path, so it can be any
;; long (nil when the path segment isn't a number) and may not exist.
(s/def ::id-arg
  (s/with-gen (s/nilable int?)
    #(gen/one-of [(gen/return nil) (gen/choose -2 60) (gen/large-integer)])))

;; --- Request bodies: JSON, keywordized ---

;; POST /api/todos and PUT /api/todos/:id. A JSON null for done means 0.
(s/def :todo.input/done (s/nilable #{0 1}))
(s/def ::todo-input (s/keys :req-un [:todo.todo/title] :opt-un [:todo.input/done]))

;; --- Ring request ---

(defn- json-stream [x]
  (java.io.ByteArrayInputStream. (.getBytes ^String (json/generate-string x) "UTF-8")))

(defn- gen-id-param
  "Path segments for /api/todos/:id: numbers, signed or zero-padded numbers,
  numbers too big for a long, and junk."
  []
  (gen/one-of [(gen/fmap str (gen/choose 1 1000))
               (gen/fmap str (gen/large-integer))
               (gen/elements ["+7" "007" "-0" "" "abc" "1e3" "9223372036854775808"])
               (gen/string-alphanumeric)]))

(s/def :todo.request/request-method #{:get :head :post :put :patch :delete :options})
(s/def :todo.request/uri
  (s/with-gen (s/and string? #(str/starts-with? % "/"))
    #(gen/fmap (fn [s] (str "/api/todos/" s)) (gen/string-alphanumeric))))
(s/def :todo.request/path-params
  (s/with-gen (s/map-of keyword? string?)
    #(gen/one-of [(gen/return {}) (gen/hash-map :id (gen-id-param))])))
(s/def :todo.request/body
  (s/nilable (s/with-gen #(instance? java.io.InputStream %)
               #(gen/fmap json-stream (s/gen ::todo-input)))))
(s/def ::request
  (s/keys :req-un [:todo.request/request-method :todo.request/uri]
          :opt-un [:todo.request/path-params :todo.request/body]))

;; --- Ring response ---

(s/def :todo.response/status (s/int-in 100 600))
(s/def :todo.response/headers (s/map-of string? string? :gen-max 4))
(s/def :todo.response/body string?)
(s/def ::response
  (s/keys :req-un [:todo.response/status]
          :opt-un [:todo.response/headers :todo.response/body]))

(defn response-with-status
  "A ::response spec whose :status is one of `codes`."
  [& codes]
  (let [allowed (set codes)]
    (s/with-gen (s/and ::response #(contains? allowed (:status %)))
      #(gen/fmap (fn [[resp status]] (assoc resp :status status))
                 (gen/tuple (s/gen ::response) (gen/elements codes))))))

;; A response built by todo.routes/json-response.
(s/def ::json-response
  (s/with-gen (s/and ::response #(= "application/json" (get-in % [:headers "Content-Type"])))
    #(gen/fmap (fn [resp] (assoc-in resp [:headers "Content-Type"] "application/json"))
               (s/gen ::response))))

;; Ring handler: request map -> response map.
(s/def ::handler
  (s/with-gen ifn?
    #(gen/fmap (fn [resp] (fn [_request] resp)) (s/gen ::response))))

;; --- JSON bodies the API sends ---

(s/def :todo.error/error string?)
(s/def ::error-body (s/keys :req-un [:todo.error/error]))
(s/def :todo.deleted/deleted :todo.todo/id)
(s/def ::deleted-body (s/keys :req-un [:todo.deleted/deleted]))

;; nonconforming, so an :fn spec can compare the body with the parsed JSON
(s/def ::json-body
  (s/nonconforming
   (s/or :todo ::todo :todos ::todos :error ::error-body :deleted ::deleted-body)))

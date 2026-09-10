(ns todo.db
  (:require [clojure.spec.alpha :as s]
            [next.jdbc :as jdbc]
            [next.jdbc.result-set :as rs]
            [todo.specs :as specs]))

(def db-spec {:dbtype "sqlite" :dbname "todos.db"})

(def datasource (delay (jdbc/get-datasource db-spec)))

(defn init-db!
  "Create the todos table if it doesn't exist."
  []
  (jdbc/execute! @datasource
                 ["CREATE TABLE IF NOT EXISTS todos (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT    NOT NULL,
        done  INTEGER NOT NULL DEFAULT 0
      )"]))

(s/fdef init-db!
  :args (s/cat))

(defn list-todos
  "Return all todos as a vector of maps."
  []
  (jdbc/execute! @datasource
                 ["SELECT id, title, done FROM todos ORDER BY id"]
                 {:builder-fn rs/as-unqualified-lower-maps}))

(s/fdef list-todos
  :args (s/cat)
  :ret ::specs/todos
  ;; ORDER BY id, and ids are unique
  :fn (fn [{:keys [ret]}]
        (let [ids (map :id ret)]
          (or (empty? ids) (apply < ids)))))

(defn get-todo
  "Return a single todo by id, or nil."
  [id]
  (jdbc/execute-one! @datasource
                     ["SELECT id, title, done FROM todos WHERE id = ?" id]
                     {:builder-fn rs/as-unqualified-lower-maps}))

(s/fdef get-todo
  :args (s/cat :id ::specs/id-arg)
  :ret (s/nilable ::specs/todo)
  :fn (fn [{{:keys [id]} :args ret :ret}]
        (or (nil? ret) (= id (:id ret)))))

(defn create-todo!
  "Insert a new todo. Returns the created row."
  [{:keys [title done] :or {done 0}}]
  (let [result (jdbc/execute-one! @datasource
                                  ["INSERT INTO todos (title, done) VALUES (?, ?)" title done]
                                  {:return-keys true
                                   :builder-fn rs/as-unqualified-lower-maps})]
    ;; SQLite returns the generated key; fetch the full row
    (get-todo (:id result (get result (keyword "last_insert_rowid()"))))))

(s/fdef create-todo!
  :args (s/cat :todo ::specs/todo-input)
  :ret ::specs/todo
  ;; the row holds what was sent; a missing or null done is stored as 0
  :fn (fn [{{:keys [todo]} :args ret :ret}]
        (= {:title (:title todo) :done (or (:done todo) 0)}
           (dissoc ret :id))))

(defn update-todo!
  "Replace a todo by id. Returns the updated row or nil."
  [id {:keys [title done]}]
  (jdbc/execute! @datasource
                 ["UPDATE todos SET title = ?, done = ? WHERE id = ?" title (or done 0) id])
  (get-todo id))

(s/fdef update-todo!
  :args (s/cat :id ::specs/id-arg :todo ::specs/todo-input)
  :ret (s/nilable ::specs/todo)
  ;; nil when no row has that id; otherwise the row is replaced wholesale
  :fn (fn [{{:keys [id todo]} :args ret :ret}]
        (or (nil? ret)
            (= {:id id :title (:title todo) :done (or (:done todo) 0)} ret))))

(defn delete-todo!
  "Delete a todo by id. Returns true if a row was deleted."
  [id]
  (let [result (jdbc/execute-one! @datasource
                                  ["DELETE FROM todos WHERE id = ?" id])]
    (pos? (:next.jdbc/update-count result 0))))

(s/fdef delete-todo!
  :args (s/cat :id ::specs/id-arg)
  :ret boolean?)

(ns todo.db
  (:require [next.jdbc :as jdbc]
            [next.jdbc.result-set :as rs]))

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

(defn list-todos
  "Return all todos as a vector of maps."
  []
  (jdbc/execute! @datasource
    ["SELECT id, title, done FROM todos ORDER BY id"]
    {:builder-fn rs/as-unqualified-lower-maps}))

(defn get-todo
  "Return a single todo by id, or nil."
  [id]
  (jdbc/execute-one! @datasource
    ["SELECT id, title, done FROM todos WHERE id = ?" id]
    {:builder-fn rs/as-unqualified-lower-maps}))

(defn create-todo!
  "Insert a new todo. Returns the created row."
  [{:keys [title done] :or {done 0}}]
  (let [result (jdbc/execute-one! @datasource
                 ["INSERT INTO todos (title, done) VALUES (?, ?)" title done]
                 {:return-keys true
                  :builder-fn rs/as-unqualified-lower-maps})]
    ;; SQLite returns the generated key; fetch the full row
    (get-todo (:id result (get result (keyword "last_insert_rowid()"))))))

(defn update-todo!
  "Replace a todo by id. Returns the updated row or nil."
  [id {:keys [title done]}]
  (jdbc/execute! @datasource
    ["UPDATE todos SET title = ?, done = ? WHERE id = ?" title (or done 0) id])
  (get-todo id))

(defn delete-todo!
  "Delete a todo by id. Returns true if a row was deleted."
  [id]
  (let [result (jdbc/execute-one! @datasource
                 ["DELETE FROM todos WHERE id = ?" id])]
    (pos? (:next.jdbc/update-count result 0))))

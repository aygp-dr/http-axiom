(ns todo.test-db
  "A throwaway SQLite database for tests: nothing touches todos.db, and
  nothing needs a network."
  (:require [next.jdbc :as jdbc]
            [todo.db :as db]))

(defn with-temp-db
  "clojure.test fixture: point todo.db at a fresh SQLite file, create the
  table, run the tests, then delete the file."
  [f]
  (let [file (java.io.File/createTempFile "todo-test" ".db")]
    (try
      (with-redefs [db/datasource (delay (jdbc/get-datasource {:dbtype "sqlite"
                                                               :dbname (str file)}))]
        (db/init-db!)
        (f))
      (finally
        (.delete file)))))

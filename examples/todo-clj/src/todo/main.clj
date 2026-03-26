(ns todo.main
  (:require [todo.db :as db]
            [todo.routes :as routes]
            [todo.middleware :as mw]
            [ring.adapter.jetty :as jetty]))

(defn -main
  [& _args]
  (db/init-db!)
  (println "todo-clj epoch 0 starting on http://localhost:8080")
  (println "WARNING: deliberately insecure -- no security headers, no auth, no CORS")
  (jetty/run-jetty (mw/wrap-epoch-0 routes/app)
                   {:port 8080 :join? true}))

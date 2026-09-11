(ns todo.db-test
  (:require [clojure.spec.test.alpha :as stest]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [todo.db :as db]
            [todo.test-db :refer [with-temp-db]]))

;; Exercise every s/fdef :args spec while the unit tests run.
(use-fixtures :once
  (fn [f] (stest/instrument) (try (f) (finally (stest/unstrument)))))

(use-fixtures :each with-temp-db)

(deftest crud-round-trip
  (let [created (db/create-todo! {:title "Write hax scenario S-011"})
        id      (:id created)]
    (is (= {:title "Write hax scenario S-011" :done 0} (dissoc created :id)))
    (is (= created (db/get-todo id)))
    (is (= [created] (db/list-todos)))
    (is (= (assoc created :title "Rotate JWT key" :done 1)
           (db/update-todo! id {:title "Rotate JWT key" :done 1})))
    (is (true? (db/delete-todo! id)))
    (is (false? (db/delete-todo! id)))
    (is (nil? (db/get-todo id)))
    (is (nil? (db/update-todo! id {:title "gone"})))))

;; The db fns write to SQLite, so specs_test leaves them out of stest/check.
;; Here their fdefs (:args, :ret, :fn) are checked against the throwaway
;; database, one fn at a time (stest/check runs fns in parallel, and SQLite
;; would report "database is locked"). create-todo! runs first so the others
;; see rows.
(deftest db-fdefs-hold-against-a-temp-db
  (doseq [sym [`db/create-todo! `db/list-todos `db/get-todo `db/update-todo! `db/delete-todo!]
          r   (stest/check sym {:clojure.spec.test.check/opts {:num-tests 50}})]
    (testing (str (:sym r))
      (is (nil? (:failure r))
          (pr-str (stest/abbrev-result r))))))

(ns todo.middleware
  (:require [clojure.spec.alpha :as s]
            [todo.specs :as specs]))

;; Epoch 0: NO security middleware.
;; No CSP, no HSTS, no X-Frame-Options, no X-Content-Type-Options,
;; no CORS headers, no auth, no CSRF protection.
;; This is deliberately insecure so hax can detect the gaps.

(defn wrap-epoch-0
  "Identity middleware. Adds nothing. That's the point."
  [handler]
  (fn [request]
    (handler request)))

(s/fdef wrap-epoch-0
  :args (s/cat :handler ::specs/handler)
  :ret ::specs/handler
  ;; epoch 0 adds nothing: the wrapped handler answers exactly like the original
  :fn (fn [{{:keys [handler]} :args ret :ret}]
        (let [request {:request-method :get :uri "/api/todos"}]
          (= (handler request) (ret request)))))

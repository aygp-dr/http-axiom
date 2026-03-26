(ns todo.middleware)

;; Epoch 0: NO security middleware.
;; No CSP, no HSTS, no X-Frame-Options, no X-Content-Type-Options,
;; no CORS headers, no auth, no CSRF protection.
;; This is deliberately insecure so hax can detect the gaps.

(defn wrap-epoch-0
  "Identity middleware. Adds nothing. That's the point."
  [handler]
  (fn [request]
    (handler request)))

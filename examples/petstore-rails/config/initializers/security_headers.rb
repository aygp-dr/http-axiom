# Epoch 1: Add missing security headers detected by hax audit
#
# Baseline (Epoch 0) failures:
#   FAIL: Content-Security-Policy missing
#   FAIL: Cross-Origin-Resource-Policy missing
#   FAIL: Strict-Transport-Security missing (skipped — no HTTPS on localhost)
#
# Baseline (Epoch 0) warnings:
#   WARN: Permissions-Policy missing
#   WARN: Cross-Origin-Embedder-Policy missing
#   WARN: Cross-Origin-Opener-Policy missing
#
# This middleware injects the headers into every response.

class SecurityHeadersMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    status, headers, response = @app.call(env)

    # Content-Security-Policy (CSP) — restrict resource loading to same origin
    headers["content-security-policy"] ||= "default-src 'self'"

    # Cross-Origin-Resource-Policy (CORP) — prevent cross-origin reads
    headers["cross-origin-resource-policy"] ||= "same-origin"

    # Cross-Origin-Embedder-Policy (COEP) — require CORP for embedded resources
    headers["cross-origin-embedder-policy"] ||= "require-corp"

    # Cross-Origin-Opener-Policy (COOP) — isolate browsing context
    headers["cross-origin-opener-policy"] ||= "same-origin"

    # Permissions-Policy — disable sensitive browser features
    headers["permissions-policy"] ||= "geolocation=(), camera=(), microphone=()"

    # Note: HSTS (Strict-Transport-Security) is intentionally omitted.
    # It requires HTTPS, which is not available on localhost development.
    # In production, configure HSTS via config.force_ssl = true in
    # config/environments/production.rb.

    [status, headers, response]
  end
end

Rails.application.config.middleware.insert_before 0, SecurityHeadersMiddleware

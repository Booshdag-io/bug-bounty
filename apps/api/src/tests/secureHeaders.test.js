const secureHeaders = require('../middleware/secureHeaders');

describe('secureHeaders middleware', () => {
  let req, res, next;

  beforeEach(() => {
    req = {};
    res = {
      headers: {},
      setHeader(name, val) {
        this.headers[name] = val;
      }
    };
    next = jest.fn();
  });

  it('sets standard defensive security headers by default', () => {
    const middleware = secureHeaders();
    middleware(req, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.headers['X-Content-Type-Options']).toBe('nosniff');
    expect(res.headers['X-Frame-Options']).toBe('DENY');
    expect(res.headers['X-XSS-Protection']).toBe('1; mode=block');
    expect(res.headers['Strict-Transport-Security']).toContain('max-age=31536000');
    expect(res.headers['Referrer-Policy']).toBe('strict-origin-when-cross-origin');
  });

  it('allows custom CSP and FrameGuard overrides', () => {
    const customCsp = "default-src 'self' https://trusted.api.com";
    const middleware = secureHeaders({
      contentSecurityPolicy: customCsp,
      frameGuard: 'SAMEORIGIN'
    });
    middleware(req, res, next);

    expect(res.headers['Content-Security-Policy']).toBe(customCsp);
    expect(res.headers['X-Frame-Options']).toBe('SAMEORIGIN');
  });
});

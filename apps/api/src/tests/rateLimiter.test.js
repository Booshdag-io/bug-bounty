const rateLimiter = require('../middleware/rateLimiter');

describe('rateLimiter middleware', () => {
  let req, res, next;

  beforeEach(() => {
    req = {
      ip: '192.168.1.1',
      connection: { remoteAddress: '192.168.1.1' }
    };
    res = {
      headers: {},
      statusCode: 200,
      setHeader(name, val) {
        this.headers[name] = val;
      },
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(payload) {
        this.body = payload;
        return this;
      }
    };
    next = jest.fn();
  });

  it('allows requests within limit', () => {
    const limiter = rateLimiter({ windowMs: 1000, max: 2 });
    limiter(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.headers['X-RateLimit-Limit']).toBe(2);
    expect(res.headers['X-RateLimit-Remaining']).toBe(1);
    limiter.stop();
  });

  it('blocks requests exceeding limit with 429', () => {
    const limiter = rateLimiter({ windowMs: 1000, max: 2 });
    limiter(req, res, next);
    limiter(req, res, next);
    expect(next).toHaveBeenCalledTimes(2);

    limiter(req, res, next);
    expect(next).toHaveBeenCalledTimes(2);
    expect(res.statusCode).toBe(429);
    expect(res.body).toEqual({ error: 'Too many requests, please try again later.' });
    expect(res.headers['Retry-After']).toBeDefined();
    limiter.stop();
  });

  it('resets correctly on limiter.reset()', () => {
    const limiter = rateLimiter({ windowMs: 1000, max: 1 });
    limiter(req, res, next);
    limiter(req, res, next);
    expect(res.statusCode).toBe(429);

    limiter.reset();
    limiter(req, res, next);
    expect(next).toHaveBeenCalledTimes(2);
    limiter.stop();
  });
});

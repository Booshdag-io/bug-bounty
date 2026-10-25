const { sanitizeHtml } = require('../utils/sanitizeHtml');

describe('sanitizeHtml utility', () => {
  it('strips script blocks and dangerous tags', () => {
    const dirty = '<script>alert(1)</script><b>Hello</b>';
    const clean = sanitizeHtml(dirty);
    expect(clean).not.toContain('<script>');
    expect(clean).not.toContain('alert(1)');
    expect(clean).toContain('&lt;b&gt;Hello&lt;/b&gt;');
  });

  it('disarms inline event handlers', () => {
    const dirty = '<img src="x" onerror="stealCookies()">';
    const clean = sanitizeHtml(dirty);
    expect(clean).not.toContain('onerror');
    expect(clean).not.toContain('stealCookies');
  });

  it('neutralizes javascript: URIs', () => {
    const dirty = '<a href="javascript:doEvil()">Click</a>';
    const clean = sanitizeHtml(dirty);
    expect(clean).not.toContain('javascript:doEvil()');
  });

  it('safely handles non-string inputs', () => {
    expect(sanitizeHtml(null)).toBe('');
    expect(sanitizeHtml(undefined)).toBe('');
    expect(sanitizeHtml(123)).toBe('');
  });
});

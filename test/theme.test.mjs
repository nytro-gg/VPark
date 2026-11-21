// Appearance: exactly two modes (Light and OLED), a one-click toggle, the pre-paint
// script that applies the stored choice, and the circular reveal's geometry/fallbacks.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import './support/register-ts.mjs';

const theme = await import('../src/lib/theme.ts');

function fakeRoot() {
  const classes = new Set();
  const attrs = new Map();
  return {
    classes,
    attrs,
    classList: {
      toggle(token, force) {
        const on = force === undefined ? !classes.has(token) : force;
        if (on) classes.add(token);
        else classes.delete(token);
        return on;
      },
      contains: (t) => classes.has(t),
    },
    setAttribute: (k, v) => attrs.set(k, v),
    getAttribute: (k) => (attrs.has(k) ? attrs.get(k) : null),
  };
}

function fakeStorage(initial = {}) {
  const data = new Map(Object.entries(initial));
  return {
    data,
    getItem: (k) => (data.has(k) ? data.get(k) : null),
    setItem: (k, v) => data.set(k, String(v)),
  };
}

/** Run the exact pre-paint script string against a fake window/document. */
function runInitScript({ stored, prefersDark = false, storageThrows = false }) {
  const root = fakeRoot();
  const storage = storageThrows
    ? {
        getItem() {
          throw new Error('blocked');
        },
        setItem() {
          throw new Error('blocked');
        },
      }
    : fakeStorage(stored === undefined ? {} : { vpark_theme: stored });
  const window = { localStorage: storage, matchMedia: () => ({ matches: prefersDark }) };
  new Function('window', 'document', theme.THEME_INIT_SCRIPT)(window, { documentElement: root });
  return { root, storage };
}

describe('two appearance modes', () => {
  it('offers exactly Light and OLED', () => {
    assert.deepEqual([...theme.THEMES], ['light', 'oled']);
    assert.equal(theme.isTheme('dark'), false);
  });

  it('toggles Light ↔ OLED in one step', () => {
    assert.equal(theme.nextTheme('light'), 'oled');
    assert.equal(theme.nextTheme('oled'), 'light');
  });

  it('migrates the retired navy "dark" preference to OLED', () => {
    assert.equal(theme.resolveTheme('dark', false), 'oled');
    assert.equal(theme.readStoredTheme(fakeStorage({ vpark_theme: 'dark' })), 'oled');
    assert.equal(theme.resolveTheme('light', true), 'light');
    assert.equal(theme.resolveTheme(null, true), 'oled');
    assert.equal(theme.resolveTheme('sepia', false), 'light');
  });

  it('applies OLED as .dark + .oled so every Tailwind dark: style still works', () => {
    const root = fakeRoot();
    theme.applyThemeToRoot(root, 'oled');
    assert.deepEqual([...root.classes].sort(), ['dark', 'oled']);
    assert.equal(root.getAttribute('data-theme'), 'oled');
    assert.equal(theme.readAppliedTheme(root), 'oled');
    theme.applyThemeToRoot(root, 'light');
    assert.deepEqual([...root.classes], []);
    assert.equal(theme.readAppliedTheme(root), 'light');
  });

  it('persists the selection under vpark_theme and survives blocked storage', () => {
    const storage = fakeStorage();
    theme.persistTheme(storage, 'oled');
    assert.equal(storage.data.get('vpark_theme'), 'oled');
    assert.equal(theme.readStoredTheme(storage), 'oled');
    const blocked = {
      getItem() {
        throw new Error('blocked');
      },
      setItem() {
        throw new Error('blocked');
      },
    };
    assert.doesNotThrow(() => theme.persistTheme(blocked, 'light'));
    assert.equal(theme.readStoredTheme(blocked), null);
  });
});

describe('pre-paint theme script', () => {
  it('applies a stored Light preference even when the OS prefers dark', () => {
    const { root } = runInitScript({ stored: 'light', prefersDark: true });
    assert.deepEqual([...root.classes], []);
    assert.equal(root.getAttribute('data-theme'), 'light');
  });

  it('applies a stored OLED preference before first paint', () => {
    const { root } = runInitScript({ stored: 'oled' });
    assert.deepEqual([...root.classes].sort(), ['dark', 'oled']);
    assert.equal(root.getAttribute('data-theme'), 'oled');
  });

  it('turns a legacy "dark" value into OLED and rewrites the stored value', () => {
    const { root, storage } = runInitScript({ stored: 'dark' });
    assert.deepEqual([...root.classes].sort(), ['dark', 'oled']);
    assert.equal(storage.data.get('vpark_theme'), 'oled');
  });

  it('follows the OS when nothing valid is stored', () => {
    assert.equal(runInitScript({ prefersDark: true }).root.getAttribute('data-theme'), 'oled');
    assert.equal(runInitScript({ prefersDark: false }).root.getAttribute('data-theme'), 'light');
    assert.equal(runInitScript({ stored: 'garbage' }).root.getAttribute('data-theme'), 'light');
  });

  it('never throws when storage is blocked', () => {
    const { root } = runInitScript({ storageThrows: true, prefersDark: true });
    assert.equal(root.getAttribute('data-theme'), 'oled');
  });

  it('is the script the root layout injects', () => {
    const layout = fs.readFileSync(new URL('../src/app/layout.tsx', import.meta.url), 'utf8');
    assert.match(layout, /THEME_INIT_SCRIPT/);
  });
});

describe('circular theme reveal', () => {
  const viewport = { width: 1440, height: 900 };
  const button = { left: 1300, top: 14, width: 36, height: 36 };

  it('starts at the pointer position for mouse/touch activation', () => {
    const g = theme.revealGeometry(button, viewport, { x: 1310, y: 30 });
    assert.equal(g.x, 1310);
    assert.equal(g.y, 30);
  });

  it('starts at the button centre for keyboard activation (no pointer / 0,0 click)', () => {
    for (const pointer of [null, { x: 0, y: 0 }]) {
      const g = theme.revealGeometry(button, viewport, pointer);
      assert.equal(g.x, 1318);
      assert.equal(g.y, 32);
    }
  });

  it('covers the farthest corner of the viewport', () => {
    const g = theme.revealGeometry(button, viewport, null);
    assert.equal(g.radius, Math.ceil(Math.hypot(1318, 900 - 32)));
    const centre = theme.revealGeometry({ left: 700, top: 430, width: 40, height: 40 }, viewport, null);
    assert.ok(centre.radius >= Math.hypot(720, 450) - 1);
  });

  it('clamps an off-screen origin into the viewport', () => {
    const g = theme.revealGeometry({ left: 1500, top: -80, width: 36, height: 36 }, viewport, null);
    assert.equal(g.x, 1440);
    assert.equal(g.y, 0);
  });

  it('falls back to a fade without View Transitions and to an instant switch for reduced motion', () => {
    assert.equal(theme.chooseTransitionMode({ hasViewTransitions: true, reducedMotion: false }), 'reveal');
    assert.equal(theme.chooseTransitionMode({ hasViewTransitions: false, reducedMotion: false }), 'fade');
    assert.equal(theme.chooseTransitionMode({ hasViewTransitions: true, reducedMotion: true }), 'instant');
    assert.equal(theme.chooseTransitionMode({ hasViewTransitions: false, reducedMotion: true }), 'instant');
  });
});

describe('reveal timing and keyframes', () => {
  const g = theme.revealGeometry({ left: 1300, top: 14, width: 36, height: 36 }, { width: 1440, height: 900 }, null);

  it('uses one continuous ease-out curve (no multi-segment keyframes that pause and lurch)', () => {
    assert.equal(theme.THEME_REVEAL_EASING, 'cubic-bezier(0.33, 1, 0.68, 1)');
    assert.ok(theme.THEME_REVEAL_DURATION_MS >= 600 && theme.THEME_REVEAL_DURATION_MS <= 900);
    const clip = theme.revealClipKeyframes(g);
    assert.equal(clip.length, 2, 'two keyframes: the timing function alone shapes the motion');
  });

  it('grows a clip-path circle from the origin to the far corner', () => {
    const [from, to] = theme.revealClipKeyframes(g);
    assert.equal(from.clipPath, `circle(0px at ${g.x}px ${g.y}px)`);
    assert.equal(to.clipPath, `circle(${g.radius}px at ${g.x}px ${g.y}px)`);
  });

  it('keeps the glow ring on the clip edge: scale is linear in the same eased progress', () => {
    const ring = theme.revealRingKeyframes(g);
    const scaleAt = (k) => Number(/scale\(([\d.]+)\)/.exec(k.transform)[1]);
    assert.equal(scaleAt(ring[0]), 0);
    for (const k of ring.slice(1)) {
      const edgeRadius = g.radius * k.offset;
      assert.ok(Math.abs(scaleAt(k) * theme.THEME_RING_PEAK_PX - edgeRadius) < 1, `ring off the edge at offset ${k.offset}`);
    }
    assert.equal(ring.at(-1).opacity, 0, 'the rim fades out as the edge leaves the viewport');
  });

  it('animates only compositor-friendly properties', () => {
    for (const k of [...theme.revealClipKeyframes(g), ...theme.revealRingKeyframes(g)]) {
      for (const prop of Object.keys(k)) assert.ok(['clipPath', 'transform', 'opacity', 'offset'].includes(prop), prop);
    }
  });
});

describe('theme styles', () => {
  const css = fs.readFileSync(new URL('../src/app/globals.css', import.meta.url), 'utf8');
  const darkBlock = css.slice(css.indexOf('\n.dark {'), css.indexOf('}', css.indexOf('\n.dark {')));

  it('uses pure #000000 for the OLED canvas and core surfaces', () => {
    assert.match(darkBlock, /--canvas-bg:\s*#000000;/);
    assert.match(darkBlock, /--surface-bg:\s*#000000;/);
    assert.match(darkBlock, /--nav-bg:\s*rgba\(0, 0, 0, 0\.9\d\);/);
  });

  it('no longer contains the retired navy palette', () => {
    for (const navy of ['#0a0f1a', '#0f1624', '#162033', '#0b111c', '#1a2740']) {
      assert.ok(!css.toLowerCase().includes(navy), `navy token ${navy} still present`);
    }
  });

  it('never animates a full-screen mask or a registered custom property per frame', () => {
    const section = css
      .slice(css.lastIndexOf('/*', css.indexOf('Signature theme switch')), css.indexOf('/* Fallback without View Transitions'))
      .replace(/\/\*[\s\S]*?\*\//g, '');
    assert.doesNotMatch(section, /@property|mask-image|@keyframes/);
    assert.match(section, /view-transition-name: vp-theme-ring/);
    assert.match(section, /html\.vp-theme-revealing \*[\s\S]*transition: none !important/);
  });

  it('defines the reveal and disables it for reduced motion', () => {
    assert.match(css, /html\.vp-theme-revealing::view-transition-new\(root\)/);
    const reduced = css.slice(css.indexOf('@media (prefers-reduced-motion: reduce)'));
    assert.match(reduced, /vp-theme-revealing::view-transition-new\(root\)[\s\S]*animation:\s*none/);
  });

  it('stops browsers and extensions from re-colouring the designed themes', () => {
    // Chromium/Edge forced "auto dark mode" honours `only light`; OLED declares `dark` itself.
    const rootBlock = css.slice(css.indexOf(':root {'), css.indexOf('}', css.indexOf(':root {')));
    assert.match(rootBlock, /color-scheme:\s*only light;/);
    assert.match(darkBlock, /color-scheme:\s*dark;/);
    const layout = fs.readFileSync(new URL('../src/app/layout.tsx', import.meta.url), 'utf8');
    assert.match(layout, /colorScheme: 'light dark'/, 'declares support for both schemes');
    assert.match(layout, /<meta name="darkreader-lock" \/>/, 'Dark Reader opt-out for a site with a native dark theme');
  });

  it('ships no theme selection menu, only the one-click toggle', () => {
    const header = fs.readFileSync(new URL('../src/components/nav/SiteHeader.tsx', import.meta.url), 'utf8');
    assert.match(header, /<ThemeToggle \/>/);
    assert.doesNotMatch(header, /ThemeMenu/);
    const toggle = fs.readFileSync(new URL('../src/components/nav/ThemeToggle.tsx', import.meta.url), 'utf8');
    assert.doesNotMatch(toggle, /role="menu"/);
  });

  it('applies theme, transition suppression and ring in one update and always cleans up', () => {
    const toggle = fs.readFileSync(new URL('../src/components/nav/ThemeToggle.tsx', import.meta.url), 'utf8');
    const update = toggle.slice(toggle.indexOf('const update = () => {'), toggle.indexOf('try {', toggle.indexOf('const update = () => {')));
    assert.match(update, /classList\.add\(REVEAL_CLASS\)[\s\S]*apply\(false\)[\s\S]*appendChild\(ring\)/);
    assert.match(toggle, /transition\.finished\.then\(finish, finish\)/);
    assert.match(toggle, /window\.setTimeout\(finish, SAFETY_MS\)/);
    assert.match(toggle, /flushSync/);
  });

  it('cancels its fill:both reveal animations on cleanup so they never stack under the next toggle', () => {
    const toggle = fs.readFileSync(new URL('../src/components/nav/ThemeToggle.tsx', import.meta.url), 'utf8');
    const cleanup = toggle.slice(toggle.indexOf('const cleanup = () => {'), toggle.indexOf('cleanupRef.current = cleanup;'));
    assert.match(cleanup, /anims\.forEach\(\(a\) => a\.cancel\(\)\)/);
    assert.match(toggle, /anims = \[\s*root\.animate\([\s\S]*root\.animate\(/, 'both Animation objects are retained');
    assert.match(toggle, /if \(cleanupRef\.current !== cleanup\) return;/, 'no animation starts after cleanup ran');
  });
});

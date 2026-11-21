'use client';

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import { MoonStar, Sun } from 'lucide-react';
import { useI18n } from '@/components/i18n/LanguageProvider';
import { useTheme } from '@/components/theme/useTheme';
import {
  THEME_REVEAL_DURATION_MS,
  THEME_REVEAL_EASING,
  THEME_RING_SIZE_PX,
  chooseTransitionMode,
  nextTheme,
  revealClipKeyframes,
  revealGeometry,
  revealRingKeyframes,
} from '@/lib/theme';

const REVEAL_CLASS = 'vp-theme-revealing';
const FADE_CLASS = 'vp-theme-fading';
const RING_CLASS = 'vp-theme-ring';
const FADE_MS = 260;
/** Cleanup still runs if a transition's promises never settle (tab hidden, browser bug). */
const SAFETY_MS = THEME_REVEAL_DURATION_MS + 1500;

type ViewTransitionLike = { ready: Promise<void>; finished: Promise<void>; skipTransition?: () => void };
type DocumentWithVT = Document & { startViewTransition?: (update: () => void) => ViewTransitionLike };

/**
 * One-click Light ↔ OLED switch.
 *
 * With the View Transition API the new theme spreads from the press point as a circle with a
 * soft glowing rim. Both moving parts run on the compositor:
 *  - `::view-transition-new(root)` gets an animated `clip-path: circle()` (WAAPI);
 *  - the rim is a small radial-gradient element captured as its own view-transition group
 *    (`view-transition-name: vp-theme-ring`) and scaled with `transform`, so its brightest
 *    band tracks the clip edge without repainting a full-screen mask every frame.
 * The theme is applied synchronously inside the transition callback (flushSync keeps the icon
 * and DOM classes in the same snapshot), and `vp-theme-revealing` is added in that same
 * callback so CSS colour transitions are suppressed without an extra style recalc. Without the
 * API the colours cross-fade briefly; with `prefers-reduced-motion` the switch is instant.
 * Clicks during a running reveal are ignored.
 */
export function ThemeToggle({ className = '' }: { className?: string }) {
  const { t } = useI18n();
  const { theme, setTheme, mounted } = useTheme();
  const busyRef = useRef(false);
  const fadeTimer = useRef<number | undefined>(undefined);
  const cleanupRef = useRef<(() => void) | null>(null);
  const [swapCount, setSwapCount] = useState(0);
  // The icon spin is skipped during the circular reveal: any main-thread animation inside the
  // live new snapshot forces it to be re-captured every frame (measured: dropped frames 60-130 ms
  // into the reveal). The reveal itself, spreading from this button, is the feedback.
  const [spinIcon, setSpinIcon] = useState(false);

  const runCleanup = useCallback(() => {
    cleanupRef.current?.();
    cleanupRef.current = null;
  }, []);

  useEffect(
    () => () => {
      window.clearTimeout(fadeTimer.current);
      document.documentElement.classList.remove(FADE_CLASS);
      runCleanup();
    },
    [runCleanup]
  );

  const onClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    if (busyRef.current) return;
    const target = nextTheme(theme);
    const root = document.documentElement;
    const doc = document as DocumentWithVT;
    const apply = (spin: boolean) =>
      flushSync(() => {
        setTheme(target);
        setSpinIcon(spin);
        setSwapCount((n) => n + 1);
      });

    const mode = chooseTransitionMode({
      hasViewTransitions: typeof doc.startViewTransition === 'function',
      reducedMotion: window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false,
    });

    if (mode === 'instant') {
      apply(true);
      return;
    }

    if (mode === 'fade') {
      window.clearTimeout(fadeTimer.current);
      root.classList.add(FADE_CLASS);
      apply(true);
      fadeTimer.current = window.setTimeout(() => root.classList.remove(FADE_CLASS), FADE_MS + 40);
      return;
    }

    // Keyboard activation reports detail 0 and no pointer position: use the button centre.
    const geometry = revealGeometry(
      event.currentTarget.getBoundingClientRect(),
      { width: window.innerWidth, height: window.innerHeight },
      event.detail > 0 ? { x: event.clientX, y: event.clientY } : null
    );
    busyRef.current = true;

    let ring: HTMLDivElement | null = null;
    let safety: number | undefined;
    // fill:'both' keeps a finished animation applied to its pseudo-element target, so it would stack
    // under the next toggle's animation (and stop the clip-path from being composited). Cancel them.
    let anims: Animation[] = [];
    const cleanup = () => {
      window.clearTimeout(safety);
      anims.forEach((a) => a.cancel());
      anims = [];
      ring?.remove();
      ring = null;
      root.classList.remove(REVEAL_CLASS);
      busyRef.current = false;
    };
    cleanupRef.current = cleanup;
    const finish = () => {
      if (cleanupRef.current === cleanup) runCleanup();
    };

    const update = () => {
      // One style recalc for everything: theme classes, transition suppression and the ring.
      root.classList.add(REVEAL_CLASS);
      apply(false);
      ring = document.createElement('div');
      ring.className = RING_CLASS;
      ring.setAttribute('aria-hidden', 'true');
      const half = THEME_RING_SIZE_PX / 2;
      ring.style.left = `${geometry.x - half}px`;
      ring.style.top = `${geometry.y - half}px`;
      document.body.appendChild(ring);
    };

    try {
      const transition = doc.startViewTransition!(update);
      safety = window.setTimeout(finish, SAFETY_MS);
      transition.ready.then(
        () => {
          if (cleanupRef.current !== cleanup) return; // already cleaned up (safety timeout / unmount)
          const timing: KeyframeAnimationOptions = {
            duration: THEME_REVEAL_DURATION_MS,
            easing: THEME_REVEAL_EASING,
            fill: 'both',
          };
          anims = [
            root.animate(revealClipKeyframes(geometry), { ...timing, pseudoElement: '::view-transition-new(root)' }),
            root.animate(revealRingKeyframes(geometry), { ...timing, pseudoElement: '::view-transition-new(vp-theme-ring)' }),
          ];
        },
        () => {
          // Skipped or failed before animating: the DOM update has still run.
        }
      );
      transition.finished.then(finish, finish);
    } catch {
      // The transition could not start (e.g. another one is running): still switch.
      if (root.getAttribute('data-theme') !== target) apply(true);
      finish();
    }
  };

  const toOled = theme !== 'oled';
  const label = toOled ? t('theme.switchToOled') : t('theme.switchToLight');
  const Icon = theme === 'oled' ? MoonStar : Sun;

  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={mounted ? label : t('theme.label')}
      title={mounted ? label : undefined}
      className={`vp-nav-control overflow-hidden ${className}`}
    >
      {mounted ? (
        <Icon
          key={`${theme}-${swapCount}`}
          className={`h-4 w-4 ${theme === 'light' ? 'text-amber-500' : 'text-[var(--accent-soft-ink)]'} ${spinIcon && swapCount > 0 ? 'animate-spin-in' : ''}`}
          aria-hidden="true"
        />
      ) : (
        <Sun className="h-4 w-4 opacity-0" aria-hidden="true" />
      )}
    </button>
  );
}

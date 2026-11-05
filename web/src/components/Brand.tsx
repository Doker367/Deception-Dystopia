import type { SVGProps } from "react";

export function BrandMark(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 40 40" fill="none" aria-hidden="true" {...props}>
      <defs>
        <linearGradient id="dystopia-mark" x1="6" y1="4" x2="34" y2="36" gradientUnits="userSpaceOnUse">
          <stop stopColor="#6fffe3" />
          <stop offset="0.55" stopColor="#35e6c4" />
          <stop offset="1" stopColor="#2d7dff" />
        </linearGradient>
      </defs>
      <path
        d="M20 3.2 34.5 11.4v17.2L20 36.8 5.5 28.6V11.4L20 3.2Z"
        stroke="url(#dystopia-mark)"
        strokeWidth="1.4"
      />
      <path
        d="M20 9.1c5.9 0 10.7 4.8 10.7 10.7S25.9 30.5 20 30.5 9.3 25.7 9.3 19.8 14.1 9.1 20 9.1Z"
        stroke="url(#dystopia-mark)"
        strokeOpacity="0.6"
        strokeWidth="1.1"
      />
      <path d="M20 13.3c3.6 0 6.5 2.9 6.5 6.5s-2.9 6.5-6.5 6.5-6.5-2.9-6.5-6.5 2.9-6.5 6.5-6.5Z" fill="url(#dystopia-mark)" fillOpacity="0.14" />
      <circle cx="20" cy="19.8" r="3" fill="url(#dystopia-mark)" />
      <path d="M20 4.2v7.1M20 28.3v7.3M6.7 12.2 13 15.8M33.3 12.2 27 15.8" stroke="url(#dystopia-mark)" strokeOpacity="0.55" strokeWidth="0.9" />
    </svg>
  );
}

export function Brand() {
  return (
    <div className="brand">
      <BrandMark className="brand-mark" />
      <div className="brand-copy">
        <span className="brand-name">DYSTOPIA</span>
        <span className="brand-sub">Security Operations</span>
      </div>
    </div>
  );
}

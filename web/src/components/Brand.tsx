import type { SVGProps } from "react";
import logoUrl from "../../../dystopia-logo-icon.png";

export function BrandMark(props: SVGProps<SVGSVGElement>) {
  return <img className="brand-logo-image" src={logoUrl} alt="DYSTOPIA" {...(props as unknown as React.ImgHTMLAttributes<HTMLImageElement>)} />;
}

export function Brand() {
  return (
    <div className="brand">
      <img className="brand-logo-image" src={logoUrl} alt="DYSTOPIA" />
      <div className="brand-copy">
        <span className="brand-name">DYSTOPIA</span>
        <span className="brand-sub">Security Operations</span>
      </div>
    </div>
  );
}

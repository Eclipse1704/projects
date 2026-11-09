import { createFileRoute } from "@tanstack/react-router";
import { useEffect } from "react";
import landingCss from "../landing/landing.css?url";
import bodyHtml from "../landing/body.html?raw";
import { initLanding } from "../landing/landing";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { name: "description", content: "Leak detection jobs typically pay $300–$1,300 in the US. See what it could add to your month." },
      { name: "theme-color", content: "#F6F4F0" },
    ],
    links: [
      { rel: "preconnect", href: "https://fonts.googleapis.com" },
      { rel: "preconnect", href: "https://fonts.gstatic.com", crossOrigin: "anonymous" },
      { rel: "stylesheet", href: "https://fonts.googleapis.com/css2?family=Inter:opsz,wght@14..32,400..900&display=swap" },
      { rel: "stylesheet", href: landingCss },
    ],
  }),
  component: Index,
});

function Index() {
  useEffect(() => {
    initLanding();
  }, []);
  return <div dangerouslySetInnerHTML={{ __html: bodyHtml }} />;
}

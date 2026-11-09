// @ts-nocheck
/* Landing page behaviour: tracking params, reveals, the walking-plumber scene, parallax, calculator. Runs once in the browser. */
export function initLanding() {
  if (typeof window === "undefined" || window.__lpInit) return;
  window.__lpInit = true;
  document.documentElement.classList.add("js");

  var UTM = "utm_source=instagram&utm_medium=bio&utm_campaign=underground_plumber", INVEST = 4500;
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  [].forEach.call(document.querySelectorAll("a[data-utm]"), function(a){
    a.href += (a.href.indexOf("?") < 0 ? "?" : "&") + UTM + "&utm_content=" + a.getAttribute("data-utm");
  });

  /* ---------- reveals + highlighter ---------- */
  var els = document.querySelectorAll(".rv, .hl");
  if ("IntersectionObserver" in window && !reduce) {
    var io = new IntersectionObserver(function(es){
      es.forEach(function(e){ if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } });
    }, {rootMargin: "0px 0px -8% 0px", threshold: .12});
    [].forEach.call(els, function(el){ io.observe(el); });
  } else {
    [].forEach.call(els, function(el){ el.classList.add("in"); });
  }

  /* ---------- header + dock ---------- */
  var hdr = document.getElementById("hdr"), dock = document.getElementById("dock"), heroBtns = document.getElementById("hero-btns");
  function chrome(){
    hdr.classList.toggle("scrolled", window.scrollY > 8);
    var r = heroBtns.getBoundingClientRect();
    var nearEnd = window.innerHeight + window.scrollY > document.body.scrollHeight - 160;
    var on = r.bottom < 0 && !nearEnd;
    dock.classList.toggle("show", on); dock.setAttribute("aria-hidden", on ? "false" : "true");
  }

  /* ---------- the scene: scroll walks the plumber to the leak ---------- */
  var NS = "http://www.w3.org/2000/svg", scene = document.getElementById("scene");
  var pro = document.getElementById("pro"), bob = document.getElementById("bob"), bars = document.getElementById("bars").children;
  var ringsG = document.getElementById("rings"), gasG = document.getElementById("gas");
  var found = document.getElementById("found"), foundRing = document.getElementById("found-ring");
  var LEAK = 560, X0 = 150, X1 = LEAK - 48, shown = 0, t0 = performance.now(), lastBeep = 0;
  var gas = [];
  for (var i = 0; i < 9; i++) {
    var c = document.createElementNS(NS, "circle"); c.setAttribute("r", 4); c.setAttribute("fill", "#111114");
    gasG.appendChild(c); gas.push({el: c, ph: i / 9, dx: (Math.random() - .5) * 16});
  }
  function scrollProgress(){
    var r = scene.getBoundingClientRect(), vh = window.innerHeight || 800;
    var p = (vh * .78 - r.top) / (r.height + vh * .2);
    return Math.max(0, Math.min(1, p));
  }
  function frame(now){
    var t = (now - t0) / 1000;
    var auto = Math.min(.22, Math.max(0, (t - .8) * .12));       // he starts walking on his own
    var target = reduce ? 1 : Math.max(scrollProgress(), auto);
    shown += (target - shown) * (reduce ? 1 : .08);
    var x = X0 + (X1 - X0) * shown, moving = Math.abs(target - shown) > .002;
    var by = moving ? -Math.abs(Math.sin(x / 9)) * 4 : 0;
    pro.setAttribute("transform", "translate(" + x.toFixed(1) + " 170)");
    bob.setAttribute("transform", "translate(0 " + by.toFixed(1) + ")");
    var cone = x + 48, d = Math.abs(cone - LEAK), lvl = Math.max(0, 1 - Math.min(d, 320) / 320);
    var hs = [3, 6, 9, 12];
    for (var k = 0; k < 4; k++) {
      var on = lvl * 4 > k + .15, h = on ? hs[k] : 3;
      bars[k].setAttribute("height", h); bars[k].setAttribute("y", -57 - h); bars[k].setAttribute("opacity", on ? 1 : .3);
    }
    // gas rising from the leak to the surface
    gas.forEach(function(g){
      var ph = (t * .45 + g.ph) % 1;
      g.el.setAttribute("cx", (LEAK + g.dx * ph + Math.sin(ph * 7 + g.dx) * 3).toFixed(1));
      g.el.setAttribute("cy", (252 - ph * 82).toFixed(1));
      g.el.setAttribute("opacity", (Math.sin(ph * Math.PI) * .9).toFixed(2));
      g.el.setAttribute("r", (4.2 - ph * 1.6).toFixed(2));
    });
    // beeps speed up near the leak
    var gap = .25 + (1 - lvl) * 1.1;
    if (!reduce && t - lastBeep > gap && shown < .995) {
      lastBeep = t;
      var r = document.createElementNS(NS, "path");
      r.setAttribute("fill", "none"); r.setAttribute("stroke", "#111114"); r.setAttribute("stroke-width", 3);
      r.dataset.t = t; r.dataset.x = cone; ringsG.appendChild(r);
    }
    [].slice.call(ringsG.children).forEach(function(r){
      var ph = (t - r.dataset.t) / .55;
      if (ph >= 1) { ringsG.removeChild(r); return; }
      var rad = 10 + 46 * ph, cx = +r.dataset.x, cy = 168;
      r.setAttribute("d", "M" + (cx - rad * .8).toFixed(1) + " " + (cy - rad * .6).toFixed(1) + " A" + rad + " " + rad + " 0 0 1 " + (cx + rad * .8).toFixed(1) + " " + (cy - rad * .6).toFixed(1));
      r.setAttribute("opacity", ((1 - ph) * .8).toFixed(2));
    });
    // found
    var f = Math.max(0, Math.min(1, (shown - .95) / .05));
    found.setAttribute("opacity", f.toFixed(2));
    found.setAttribute("transform", "translate(" + (LEAK + 120) + " " + (128 - 10 * f).toFixed(1) + ")");
    var pulse = f > 0 ? (t * .9) % 1 : 0;
    foundRing.setAttribute("r", (20 + 26 * pulse).toFixed(1));
    foundRing.setAttribute("opacity", (f * (1 - pulse)).toFixed(2));
    chrome();
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
  window.addEventListener("scroll", chrome, {passive: true});

  /* ---------- product parallax ---------- */
  var ph = document.getElementById("prod-ph"), img = document.getElementById("prod-img");
  function parallax(){
    if (reduce) return;
    var r = ph.getBoundingClientRect(), vh = window.innerHeight;
    var p = (r.top + r.height / 2 - vh / 2) / vh;
    img.style.transform = "translateY(" + (p * -36).toFixed(1) + "px) rotate(" + (p * -3).toFixed(2) + "deg)";
  }
  window.addEventListener("scroll", parallax, {passive: true}); parallax();

  /* ---------- calculator ---------- */
  var price = document.getElementById("price"), calls = document.getElementById("calls");
  var monthEl = document.getElementById("month"), coins = document.getElementById("coins");
  for (var j = 0; j < 20; j++) coins.appendChild(document.createElement("i"));
  var fmt = function(n){ return "$" + Math.round(n).toLocaleString("en-US"); };
  var shownMonth = 0, goal = 0, counting = false, calcSeen = false;
  function fill(r){ r.style.setProperty("--p", ((r.value - r.min) / (r.max - r.min) * 100) + "%"); }
  function tick(){
    shownMonth += (goal - shownMonth) * .16;
    if (Math.abs(goal - shownMonth) < 1) shownMonth = goal;
    monthEl.textContent = fmt(shownMonth);
    if (shownMonth !== goal) requestAnimationFrame(tick); else counting = false;
  }
  function update(){
    var p = +price.value, c = +calls.value, m = p * c;
    fill(price); fill(calls);
    document.getElementById("price-out").textContent = fmt(p);
    document.getElementById("calls-out").textContent = c;
    document.getElementById("detail").textContent = fmt(m * 12) + " a year · detector covered in about " + Math.ceil(INVEST / p) + " jobs";
    [].forEach.call(coins.children, function(el, k){ el.classList.toggle("on", k < c); });
    goal = m;
    if (reduce || !calcSeen) { shownMonth = m; monthEl.textContent = fmt(m); return; }
    if (!counting) { counting = true; requestAnimationFrame(tick); }
  }
  price.addEventListener("input", update); calls.addEventListener("input", update); update();
  if ("IntersectionObserver" in window && !reduce) {
    var cio = new IntersectionObserver(function(es){
      if (es[0].isIntersecting && !calcSeen) { calcSeen = true; shownMonth = 0; goal = +price.value * +calls.value; counting = true; requestAnimationFrame(tick); cio.disconnect(); }
    }, {threshold: .4});
    cio.observe(document.querySelector(".result"));
  } else { calcSeen = true; }

}

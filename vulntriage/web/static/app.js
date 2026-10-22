// Crosshair + tooltip for the dashboard's small line charts. Values come from data-*
// attributes rendered server-side and are inserted with textContent only.
document.querySelectorAll("[data-chart]").forEach((chart) => {
  const svg = chart.querySelector("svg");
  const hit = svg.querySelector(".hit");
  const cross = svg.querySelector(".crosshair");
  const dots = Array.from(svg.querySelectorAll(".dot"));
  const tip = chart.querySelector(".tooltip");
  if (!hit || !dots.length) return;
  const toSvgX = (clientX) => {
    const box = svg.getBoundingClientRect();
    return ((clientX - box.left) / box.width) * svg.viewBox.baseVal.width;
  };
  const show = (dot) => {
    dots.forEach((d) => d.classList.toggle("active", d === dot));
    const x = Number(dot.dataset.x);
    cross.setAttribute("x1", x);
    cross.setAttribute("x2", x);
    chart.classList.add("hovering");
    tip.querySelector("strong").textContent = dot.dataset.value;
    tip.querySelector("span").textContent = dot.dataset.label;
    tip.style.left = `${(x / svg.viewBox.baseVal.width) * 100}%`;
    tip.hidden = false;
  };
  const hide = () => {
    chart.classList.remove("hovering");
    tip.hidden = true;
    dots.forEach((d) => d.classList.remove("active"));
  };
  hit.addEventListener("pointermove", (e) => {
    const x = toSvgX(e.clientX);
    let best = dots[0];
    for (const d of dots) {
      if (Math.abs(Number(d.dataset.x) - x) < Math.abs(Number(best.dataset.x) - x)) best = d;
    }
    show(best);
  });
  hit.addEventListener("pointerleave", hide);
  svg.setAttribute("tabindex", "0");
  let idx = dots.length - 1;
  svg.addEventListener("focus", () => show(dots[idx]));
  svg.addEventListener("blur", hide);
  svg.addEventListener("keydown", (e) => {
    if (e.key === "ArrowLeft") idx = Math.max(0, idx - 1);
    else if (e.key === "ArrowRight") idx = Math.min(dots.length - 1, idx + 1);
    else return;
    e.preventDefault();
    show(dots[idx]);
  });
});

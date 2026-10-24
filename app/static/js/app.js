(function () {
  const el = document.getElementById("threatChart");
  if (!el || !window.Chart) return;

  Chart.defaults.color = "#8a9bb8";
  Chart.defaults.borderColor = "#1f2b45";

  const mk = (id, cfg) => {
    const canvas = document.getElementById(id);
    if (!canvas) return null;
    return new Chart(canvas, cfg);
  };

  fetch("/dashboard/data?days=14").then(r => r.json()).then(d => {
    // Daily email activity bar chart
    mk("threatChart", {
      type: "bar",
      data: {
        labels: d.labels.map(l => l.slice(5)),
        datasets: [
          { label: "Threats held", data: d.daily_threats, backgroundColor: "#f87171" },
          { label: "Clean", data: d.daily_clean, backgroundColor: "#22d3a6" }
        ]
      },
      options: {
        responsive: true,
        scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } }
      }
    });

    // Email verdict doughnut
    const vk = Object.keys(d.by_verdict || {});
    mk("verdictChart", {
      type: "doughnut",
      data: {
        labels: vk.length ? vk : ["none"],
        datasets: [{
          data: vk.length ? vk.map(k => d.by_verdict[k]) : [1],
          backgroundColor: vk.length ? ["#f87171", "#fbbf24", "#a78bfa", "#7dd3fc"] : ["#1f2b45"],
          borderWidth: 0
        }]
      },
      options: { plugins: { legend: { position: "bottom" } } }
    });

    // Threat level doughnut
    const lk = Object.keys(d.by_level || {});
    const levelColors = { critical: "#f87171", high: "#fb923c", medium: "#fbbf24", low: "#7dd3fc", safe: "#4ade80" };
    mk("levelChart", {
      type: "doughnut",
      data: {
        labels: lk.length ? lk : ["none"],
        datasets: [{
          data: lk.length ? lk.map(k => d.by_level[k]) : [1],
          backgroundColor: lk.length ? lk.map(k => levelColors[k] || "#8a9bb8") : ["#1f2b45"],
          borderWidth: 0
        }]
      },
      options: { plugins: { legend: { position: "bottom" } } }
    });

    // Source breakdown doughnut (email + SMS combined)
    const sk = Object.keys(d.by_source || {});
    const sourceColors = { imap: "#7dd3fc", manual: "#a78bfa", api: "#fbbf24", gmail: "#4ade80", sms: "#fb923c", whatsapp: "#22d3a6" };
    mk("sourceChart", {
      type: "doughnut",
      data: {
        labels: sk.length ? sk : ["none"],
        datasets: [{
          data: sk.length ? sk.map(k => d.by_source[k]) : [1],
          backgroundColor: sk.length ? sk.map(k => sourceColors[k] || "#8a9bb8") : ["#1f2b45"],
          borderWidth: 0
        }]
      },
      options: { plugins: { legend: { position: "bottom" } } }
    });
  });
})();

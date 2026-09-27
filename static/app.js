const preloader = document.getElementById("preloader");
window.addEventListener("load", () => setTimeout(() => preloader.classList.add("hide"), 900));

const form = document.getElementById("searchForm");
const box = document.getElementById("resultBox");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const params = new URLSearchParams(new FormData(form));
  box.classList.remove("hidden");
  box.innerHTML = '<span class="result-good">جاري البحث عن النتيجة...</span>';
  try {
    const res = await fetch("/api/results?" + params.toString());
    const data = await res.json();
    if (!data.length) {
      box.innerHTML = '<span class="result-empty">لم نجد نتيجة مطابقة حاليًا. تأكد من البيانات أو أعد المحاولة لاحقًا.</span>';
      return;
    }
    box.innerHTML = data.map(r => `
      <div class="result-row">
        <h3>${r.name || "الطالب"}</h3>
        <p>رقم الاكتتاب: <b>${r.seat_number || "-"}</b> · الفرع: <b>${r.branch || "-"}</b> · المحافظة: <b>${r.governorate || "-"}</b></p>
        <p>النتيجة: <b>${r.total ?? "-"} / ${r.max ?? "-"}</b></p>
      </div>`).join("");
  } catch {
    box.innerHTML = '<span class="result-empty">تعذر الاتصال بالخادم. تأكد أن Termux ما زال يشغّل الموقع.</span>';
  }
});

document.querySelectorAll(".branch-card button").forEach(btn => {
  btn.addEventListener("click", () => {
    document.getElementById("branch").value = btn.dataset.branch;
    document.getElementById("results").scrollIntoView({behavior:"smooth"});
  });
});

document.getElementById("themeBtn").addEventListener("click", () => {
  document.body.classList.toggle("light");
  document.getElementById("themeBtn").textContent =
    document.body.classList.contains("light") ? "☀" : "☾";
});

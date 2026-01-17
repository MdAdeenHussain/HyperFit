function scrollToSection(id) {
  const el = document.getElementById(id);
  if (el) {
    el.scrollIntoView({ behavior: "smooth" });
  }
}
    
function openMobileMenu() {
  document.getElementById("mobileMenu").classList.add("active");
  document.getElementById("mobileOverlay").classList.add("active");
  document.body.classList.add("menu-open");
}

function closeMobileMenu() {
  document.getElementById("mobileMenu").classList.remove("active");
  document.getElementById("mobileOverlay").classList.remove("active");
  document.body.classList.remove("menu-open");
}

document.querySelector(".newsletter-form").addEventListener("submit", function(e) {
  e.preventDefault();
  alert("Thank you for subscribing!");
});

function openSearch() {
  document.getElementById("searchOverlay").classList.add("active");
}

function closeSearch() {
  document.getElementById("searchOverlay").classList.remove("active");
}



// NEW CODE
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener("click", function (e) {
    const target = document.querySelector(this.getAttribute("href"));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: "smooth" });
    }
  });
});
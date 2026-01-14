function scrollToSection(id) {
      const el = document.getElementById(id);
      if (el) {
        el.scrollIntoView({ behavior: "smooth" });
      }
    }
    
    function toggleMenu() {
      document.getElementById("mobileMenu").classList.add("active");
      document.getElementById("mobileOverlay").classList.add("active");
    }

    function closeMenu() {
      document.getElementById("mobileMenu").classList.remove("active");
      document.getElementById("mobileOverlay").classList.remove("active");

      // close all dropdowns
      document.querySelectorAll(".dropdown").forEach(d => {
        d.style.maxHeight = null;
      });
    }

    function toggleDropdown(id) {
      const dropdown = document.getElementById(id);

      // close others
      document.querySelectorAll(".dropdown").forEach(d => {
        if (d !== dropdown) d.style.maxHeight = null;
      });

      if (dropdown.style.maxHeight) {
        dropdown.style.maxHeight = null;
      } else {
        dropdown.style.maxHeight = dropdown.scrollHeight + "px";
      }
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

const menCategories = [
  { name: "Tshirts", price: "₹299", img: "/static/images/product1.png" },
  { name: "Joggers", price: "₹539", img: "/static/images/product2.png" },
  { name: "Stringers", price: "₹299", img: "/static/images/product3.png" },
  { name: "Hoodies", price: "₹699", img: "/static/images/product4.png" }
];

const womenCategories = [
  { name: "Sports Bra", price: "₹399", img: "/static/images/product4.png" },
  { name: "Leggings", price: "₹499", img: "/static/images/product3.png" },
  { name: "Tops", price: "₹349", img: "/static/images/product2.png" },
  { name: "Hoodies", price: "₹749", img: "/static/images/product1.png" }
];

const grid = document.getElementById("categoryGrid");

function render(categories) {
  grid.innerHTML = "";
  categories.forEach(c => {
    grid.innerHTML += `
      <div class="category-card">
        <img src="${c.img}">
        <h3>${c.name}</h3>
        <p class="price">Starts from ${c.price}</p>
      </div>
    `;
  });
}

function showMen() {
  document.querySelectorAll(".toggle button")[0].classList.add("active");
  document.querySelectorAll(".toggle button")[1].classList.remove("active");
  render(menCategories);
}

function showWomen() {
  document.querySelectorAll(".toggle button")[1].classList.add("active");
  document.querySelectorAll(".toggle button")[0].classList.remove("active");
  render(womenCategories);
}

showMen(); // default

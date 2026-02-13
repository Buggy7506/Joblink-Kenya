document.getElementById("root").innerHTML = `
  <h3>Canva App Connected</h3>
  <button id="btn">Test Button</button>
`;

document.getElementById("btn").onclick = () => {
  alert("Canva frontend is working!");
};

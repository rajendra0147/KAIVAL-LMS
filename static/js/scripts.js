// Placeholder for custom JS
console.log("Library Management System Loaded");


document.addEventListener("DOMContentLoaded", function () {
    // Hide flash messages after 5 seconds
    const flashes = document.querySelectorAll(".alert");
    flashes.forEach(function (alert) {
        setTimeout(function () {
            alert.style.display = "none";
        }, 5000); // 5000 milliseconds = 5 seconds
    });
});

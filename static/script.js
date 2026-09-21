
document.addEventListener("DOMContentLoaded", function () {
    const dateInput = document.querySelector('input[name="session_date"]');

    if (dateInput) {
        const today = new Date().toISOString().split("T")[0];
        dateInput.setAttribute("min", today);
    }

    const alerts = document.querySelectorAll(".alert");

    alerts.forEach(function (alert) {
        setTimeout(function () {
            const closeButton = alert.querySelector(".btn-close");

            if (closeButton) {
                closeButton.click();
            }
        }, 5000);
    });
});
```

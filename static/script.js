document.addEventListener("DOMContentLoaded", () => {
  const inputFile = document.getElementById("fileInput");
  const display = document.getElementById("display");
  const form = document.getElementById("form");
  const errorMessage = document.getElementById("error-message");
  const otpForm = document.getElementById("otp-form")
  const otpDiv = document.getElementById("otp-div");
  const userOtpElement = document.getElementById("userOtp");
  const systemOtpElement = document.getElementById("systemOtp");
  const invalidDiv = document.getElementById("invalid");

  if (otpForm) {
    otpForm.addEventListener("submit", (event) => {
      const userOtp = userOtpElement.value
      const systemOtp = systemOtpElement.textContent.trim()
      const processing = `
      <div class="flex flex-col justify-center items-center gap-4">
      <span class="text-2xl text-gray-500">OTP Validated</span>
      <div class="flex justify-center items-center gap-4">
      <div class="spinner"></div> <!-- Assuming you have CSS for spinner -->
      <span class="text-lg text-gray-400">Untangling the rest of your document...</span>
      </div>
      </div>
      `
      const invalidMessage = `
      <p>Your OTP was incorrect. Please try again</p>
      `
      if (userOtp === systemOtp) {
        console.log("OTP Correct")
        otpDiv.innerHTML = processing
        invalidDiv.innerHTML = ""
      } else {
        event.preventDefault()
        console.log("OTP Incorrect")
        invalidDiv.innerHTML = invalidMessage
      }
    })
  }


  if (inputFile) {
    inputFile.addEventListener("change", uploadFile);
  }

  function uploadFile() {
    const file = inputFile.files[0];
    if (file) {
      const fileInfo = `
        <div class="flex flex-col justify-center items-center gap-4">
          <span class="text-2xl text-gray-500">${file.name}</span>
          <span class="text-lg text-gray-400">✅ Ready to process</span>
        </div>
      `;
      display.innerHTML = fileInfo;
    } else {
      display.innerHTML = `<p class="font-medium text-gray-500 text-xl">Please select a file</p>`;
    }
  }

  if (form) {

    form.addEventListener("submit", (event) => {
      const file = inputFile.files[0];
      const emailInput = document.getElementById('emailID').value;
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      const processing = `
      <div class="flex flex-col justify-center items-center gap-4">
      <span class="text-2xl text-gray-500">${file.name}</span>
      <div class="flex justify-center items-center gap-4">
      <div class="spinner"></div> <!-- Assuming you have CSS for spinner -->
      <span class="text-lg text-gray-400">Untangling your document...</span>
      </div>
      </div>
      `

      if (!file) {
        errorMessage.textContent = "Please select a file.";
        event.preventDefault(); // Prevent form submission
        return;
      } else {
        display.innerHTML = processing;
      }

      if (!emailRegex.test(emailInput)) {
        errorMessage.textContent = "Please enter a valid email address.";
        event.preventDefault(); // Prevent form submission
        return;
      }

      errorMessage.textContent = ""; // Clear any previous error messages
    });
  }

});

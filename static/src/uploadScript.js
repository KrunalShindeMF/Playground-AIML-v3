// Function to update the file upload display
function updateFileDisplay(file) {
  const displayDiv = document.getElementById('display');
  displayDiv.innerHTML = `
  <p class="text-lg text-stone-500 text-center">
      ${file.name}
  </p>
  <p class="text-sm text-cyan-600 text-center">
      File uploaded successfully
  </p>
  `;
}

// Function to show processing spinner
function showProcessingSpinner() {
  const displayDiv = document.getElementById('display');
  displayDiv.innerHTML = `
  <svg class="animate-spin h-10 w-10 text-cyan-500 mx-auto mb-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
  </svg>
  <p class="text-lg text-stone-500 text-center">
      Processing...
  </p>
  `;
}

// Function to check if an app is selected
function isAppSelected() {
  return document.querySelector('input[name="selectedProject"]:checked') !== null;
}

// Function to display error message
function displayError(message) {
  const errorDiv = document.getElementById('errorMessage');
  errorDiv.textContent = message;
  errorDiv.classList.remove('hidden');
}

// Function to clear error message
function clearError() {
  const errorDiv = document.getElementById('errorMessage');
  errorDiv.textContent = '';
  errorDiv.classList.add('hidden');
}

// Event listener for file input change
document.getElementById('fileInput').addEventListener('change', function(event) {
  const file = event.target.files[0];
  if (file) {
      updateFileDisplay(file);
  }
});

// Event listener for form submission
document.getElementById('form').addEventListener('submit', function(event) {
  clearError();
  if (!isAppSelected()) {
      event.preventDefault();
      displayError('Please select an app before submitting.');
      return;
  }
  const fileInput = document.getElementById('fileInput');
  if (fileInput.files.length === 0) {
      event.preventDefault();
      displayError('Please upload a file before submitting.');
      return;
  }

  // Show processing spinner when the form is successfully submitted
  showProcessingSpinner();
});

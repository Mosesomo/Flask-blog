document.addEventListener('DOMContentLoaded', function() {
  document.body.addEventListener('click', function(event) {
    if (event.target.matches('.toggle-content')) {
      event.preventDefault();

      var toggleButton = event.target;
      var contentContainer = toggleButton.parentNode;
      var truncatedContent = contentContainer.querySelector('.truncated-content');
      var fullContentSpan = contentContainer.querySelector('.full-content');

      if (truncatedContent && fullContentSpan) {
        if (fullContentSpan.style.display === 'none' || fullContentSpan.style.display === '') {
          truncatedContent.style.display = 'none';
          fullContentSpan.style.display = 'inline';
          toggleButton.textContent = 'Read Less';
        } else {
          fullContentSpan.style.display = 'none';
          truncatedContent.style.display = 'inline';
          toggleButton.textContent = 'Read More';
        }
      } else {
        console.error('Could not find truncated-content or full-content elements.');
      }
    }
  });
});

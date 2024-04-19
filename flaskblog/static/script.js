document.addEventListener('DOMContentLoaded', function() {
    var toggleLinks = document.querySelectorAll('.toggle-content');
    toggleLinks.forEach(function(link) {
       link.addEventListener('click', function(event) {
         event.preventDefault();
         var fullContent = this.getAttribute('data-full-content');
         var truncatedContent = this.parentNode.querySelector('.truncated-content');
         var fullContentSpan = this.parentNode.querySelector('.full-content');
         if (fullContentSpan.style.display === 'none') {
           // Show full content
           truncatedContent.style.display = 'none';
           fullContentSpan.style.display = 'inline';
           this.textContent = 'Show Less';
         } else {
           // Show truncated content
           fullContentSpan.style.display = 'none';
           truncatedContent.style.display = 'inline';
           this.textContent = 'Read More';
         }
       });
    });
   });
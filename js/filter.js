/**
 * WEBSITE TRƯỜNG THPT CHUYÊN PHAN BỘI CHÂU - NGHỆ AN
 * Category Filtering & Lightbox Gallery
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Generic Category Filter Tabs
  const filterBtns = document.querySelectorAll('.filter-btn');
  const filterCards = document.querySelectorAll('[data-category]');

  if (filterBtns.length > 0 && filterCards.length > 0) {
    filterBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        // Toggle active button
        filterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const filterValue = btn.getAttribute('data-filter');

        filterCards.forEach(card => {
          const cardCategory = card.getAttribute('data-category');
          if (filterValue === 'all' || cardCategory.includes(filterValue)) {
            card.style.display = '';
            card.style.animation = 'fadeIn 0.4s ease forwards';
          } else {
            card.style.display = 'none';
          }
        });
      });
    });
  }

  // 2. Lightbox Modal Preview
  const lightboxModal = document.getElementById('lightboxModal');
  const lightboxImg = document.getElementById('lightboxImg');
  const lightboxVideo = document.getElementById('lightboxVideo');
  const lightboxCaption = document.getElementById('lightboxCaption');
  const lightboxClose = document.getElementById('lightboxClose');

  const galleryItems = document.querySelectorAll('.gallery-card, .activity-item');

  if (lightboxModal && galleryItems.length > 0) {
    const closeModal = () => {
      lightboxModal.classList.remove('active');
      if (lightboxVideo) {
        lightboxVideo.pause();
        lightboxVideo.src = '';
        lightboxVideo.style.display = 'none';
      }
    };

    galleryItems.forEach(item => {
      item.addEventListener('click', () => {
        const videoSrc = item.getAttribute('data-video-src');
        const img = item.querySelector('img');
        const captionText = item.querySelector('h5') ? item.querySelector('h5').innerText : (img ? img.alt : '');
        
        if (videoSrc) {
          if (lightboxImg) lightboxImg.style.display = 'none';
          if (lightboxVideo) {
            lightboxVideo.style.display = 'block';
            lightboxVideo.src = videoSrc;
            lightboxVideo.play().catch(() => {});
          }
          if (lightboxCaption) lightboxCaption.innerText = captionText;
          lightboxModal.classList.add('active');
        } else if (img && lightboxImg) {
          if (lightboxVideo) {
            lightboxVideo.pause();
            lightboxVideo.src = '';
            lightboxVideo.style.display = 'none';
          }
          lightboxImg.style.display = 'block';
          lightboxImg.src = img.src;
          if (lightboxCaption) lightboxCaption.innerText = captionText;
          lightboxModal.classList.add('active');
        }
      });
    });

    if (lightboxClose) {
      lightboxClose.addEventListener('click', closeModal);
    }

    lightboxModal.addEventListener('click', (e) => {
      if (e.target === lightboxModal) {
        closeModal();
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && lightboxModal.classList.contains('active')) {
        closeModal();
      }
    });
  }
});

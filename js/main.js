/**
 * WEBSITE TRƯỜNG THPT CHUYÊN PHAN BỘI CHÂU - NGHỆ AN
 * Main JavaScript Interactions
 */

document.addEventListener('DOMContentLoaded', () => {
  // 1. Mobile Menu Toggle
  const mobileToggle = document.querySelector('.mobile-toggle');
  const navMenu = document.querySelector('.nav-menu');

  if (mobileToggle && navMenu) {
    mobileToggle.addEventListener('click', () => {
      navMenu.classList.toggle('active');
      const icon = mobileToggle.querySelector('i');
      if (icon) {
        icon.classList.toggle('fa-bars');
        icon.classList.toggle('fa-xmark');
      }
    });
  }

  // Mobile Submenu Accordion
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    const link = item.querySelector('.nav-link');
    const dropdown = item.querySelector('.dropdown-menu');
    if (dropdown && link && window.innerWidth <= 992) {
      link.addEventListener('click', (e) => {
        // If has dropdown and on small screens, toggle
        if (window.innerWidth <= 992) {
          e.preventDefault();
          item.classList.toggle('dropdown-open');
        }
      });
    }
  });

  // 2. Search Modal
  const searchTriggers = document.querySelectorAll('.btn-search-trigger');
  const searchModal = document.getElementById('searchModal');
  const searchClose = document.getElementById('searchClose');
  const searchInput = document.getElementById('searchInput');
  const searchResults = document.getElementById('searchResults');

  // Search items index
  const siteIndex = [
    { title: 'Lịch sử hình thành trường THPT Chuyên Phan Bội Châu', url: 'pages/gioi-thieu.html#lich-su', category: 'Giới thiệu' },
    { title: 'Tầm nhìn & Sứ mệnh trường Chuyên Phan Bội Châu', url: 'pages/gioi-thieu.html#tam-nhin', category: 'Giới thiệu' },
    { title: 'Ban giám hiệu & Cơ sở vật chất nhà trường', url: 'pages/gioi-thieu.html#bgh', category: 'Giới thiệu' },
    { title: 'Các lớp chuyên: Toán, Tin, Lý, Hóa, Sinh, Văn, Anh...', url: 'pages/hoc-tap.html#chuyen', category: 'Học tập' },
    { title: 'Tài liệu học tập & Kho đề thi chuyên chọn lọc', url: 'pages/hoc-tap.html#tai-lieu', category: 'Học tập' },
    { title: 'Khuôn viên và cơ sở vật chất nhà trường', url: 'pages/gioi-thieu.html#co-so-vat-chat', category: 'Giới thiệu' },
    { title: 'Bảng vàng thành tích học sinh giỏi Quốc tế (Olympic) & Quốc gia', url: 'pages/thanh-tich.html', category: 'Thành tích' },
    { title: 'Câu lạc bộ và hoạt động ngoại khóa học sinh Phan', url: 'pages/hoc-sinh.html', category: 'Học sinh' },
    { title: 'CP The News - CLB Nội san & Báo chí học sinh Chuyên Phan', url: 'pages/hoc-sinh.html', category: 'Học sinh' },
    { title: 'Phan Debate Club (PDC) - CLB Tranh biện Chuyên Phan', url: 'pages/hoc-sinh.html', category: 'Học sinh' },
    { title: 'Phan Acoustic Club (PAC) - CLB Âm nhạc Chuyên Phan', url: 'pages/hoc-sinh.html', category: 'Học sinh' },
    { title: 'Phan Bookaholic Club (PBC) - CLB Sách & Văn hóa đọc', url: 'pages/hoc-sinh.html', category: 'Học sinh' },
    { title: 'Phan Olympia Club (POC) - CLB Đường lên đỉnh Olympia', url: 'pages/hoc-sinh.html', category: 'Học sinh' },
    { title: 'Đội ngũ giáo viên - Các tổ bộ môn chuyên môn', url: 'pages/giao-vien.html', category: 'Giáo viên' },
    { title: 'Thư viện hình ảnh & Video kỷ yếu nhà trường', url: 'pages/thu-vien.html', category: 'Thư viện' },
    { title: 'Kỷ lục 113 giải Học sinh giỏi Quốc gia (10 giải Nhất)', url: 'pages/tin-tuc.html', category: 'Tin tức' },
    { title: 'Bảng vàng Olympic: HCV Toán học Võ Trọng Khải, HCV Vật lý Nguyễn Thế Quân', url: 'pages/tin-tuc.html', category: 'Tin tức' },
    { title: 'Mở lớp chuyên Tiếng Hàn & Phân tách 2 lớp Chuyên Toán 1, Toán 2', url: 'pages/tin-tuc.html', category: 'Tin tức' },
    { title: 'Hội nghị Cán bộ Viên chức: Chuyển đổi số và ứng dụng AI trong giảng dạy', url: 'pages/tin-tuc.html', category: 'Tin tức' },
    { title: 'Địa điểm nhà trường & Bản đồ vị trí: 119 Lê Hồng Phong, TP. Vinh', url: 'pages/dia-diem.html', category: 'Địa điểm' }
  ];

  if (searchTriggers && searchModal) {
    searchTriggers.forEach(btn => {
      btn.addEventListener('click', () => {
        searchModal.classList.add('active');
        if (searchInput) searchInput.focus();
      });
    });

    if (searchClose) {
      searchClose.addEventListener('click', () => {
        searchModal.classList.remove('active');
      });
    }

    searchModal.addEventListener('click', (e) => {
      if (e.target === searchModal) {
        searchModal.classList.remove('active');
      }
    });

    // Helper hàm an toàn chống tấn công Cross-Site Scripting (XSS Sanitizer)
    const escapeHTML = (str) => {
      if (!str) return '';
      return str.replace(/[&<>'"]/g, 
        tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
      );
    };

    // Handle Search typing
    if (searchInput && searchResults) {
      searchInput.addEventListener('input', (e) => {
        const rawQuery = e.target.value.trim();
        const safeQuery = escapeHTML(rawQuery);
        const query = rawQuery.toLowerCase();
        if (query.length === 0) {
          searchResults.innerHTML = '';
          return;
        }

        const matches = siteIndex.filter(item => 
          item.title.toLowerCase().includes(query) || 
          item.category.toLowerCase().includes(query)
        );

        if (matches.length === 0) {
          searchResults.innerHTML = `<p style="padding: 12px; color: #64748b; font-size: 0.9rem;">Không tìm thấy kết quả phù hợp với "<strong>${safeQuery}</strong>"</p>`;
        } else {
          // Adjust url if inside pages/
          const isPagesSubdir = window.location.pathname.includes('/pages/');
          searchResults.innerHTML = matches.map(m => {
            let targetUrl = m.url;
            if (isPagesSubdir) {
              targetUrl = m.url.startsWith('pages/') ? m.url.replace('pages/', '') : '../' + m.url;
            }
            return `
              <a href="${targetUrl}" style="display: block; padding: 10px 14px; border-bottom: 1px solid #e2e8f0; text-decoration: none;">
                <div style="font-weight: 600; color: #0b3c68; font-size: 0.95rem;">${m.title}</div>
                <div style="font-size: 0.78rem; color: #d97706; font-weight: 600; text-transform: uppercase;">${m.category}</div>
              </a>
            `;
          }).join('');
        }
      });
    }
  }

  // 3. Stats Animated Counter
  const statNumbers = document.querySelectorAll('.stat-number');
  if (statNumbers.length > 0) {
    let animated = false;
    const animateCounters = () => {
      statNumbers.forEach(counter => {
        const target = +counter.getAttribute('data-target');
        const duration = 1500;
        const stepTime = 20;
        const totalSteps = duration / stepTime;
        const increment = target / totalSteps;
        let current = 0;

        const timer = setInterval(() => {
          current += increment;
          if (current >= target) {
            counter.innerText = target + (counter.getAttribute('data-suffix') || '');
            clearInterval(timer);
          } else {
            counter.innerText = Math.floor(current) + (counter.getAttribute('data-suffix') || '');
          }
        }, stepTime);
      });
    };

    const handleScrollCounter = () => {
      const statsSection = document.querySelector('.stats-section');
      if (!statsSection) return;
      const rect = statsSection.getBoundingClientRect();
      if (rect.top <= window.innerHeight - 80 && !animated) {
        animated = true;
        animateCounters();
      }
    };

    window.addEventListener('scroll', handleScrollCounter);
    handleScrollCounter(); // check on load
  }

  // 4. Back to Top Button
  const backToTopBtn = document.querySelector('.back-to-top');
  if (backToTopBtn) {
    window.addEventListener('scroll', () => {
      if (window.scrollY > 350) {
        backToTopBtn.classList.add('show');
      } else {
        backToTopBtn.classList.remove('show');
      }
    });

    backToTopBtn.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // 5. Contact Form submission demo
  const contactForm = document.getElementById('schoolContactForm');
  if (contactForm) {
    contactForm.addEventListener('submit', (e) => {
      e.preventDefault();
      alert('Cảm ơn bạn đã gửi liên hệ tới Ban Giám Hiệu THPT Chuyên Phan Bội Châu! Chúng tôi sẽ phản hồi sớm nhất.');
      contactForm.reset();
    });
  }
});

/**
 * File preview functionality for the temporary storage application
 */

class FilePreviewManager {
    constructor(linkId) {
        this.linkId = linkId;
        this.previewModal = document.getElementById('previewModal');
        this.previewContainer = document.getElementById('previewContainer');
        this.previewFilename = document.getElementById('previewFilename');
        this.previewableFiles = [];
        this.currentIndex = 0;

        // Initialize event listeners
        this.initEventListeners();

        // Также добавляем обработчик событий для кнопок с onclick
        this.setupInlineEventHandlers();
    }

    // Initialize event listeners
    initEventListeners() {
        document.getElementById('previewClose').addEventListener('click', () => this.closePreview());
        document.getElementById('previewPrev').addEventListener('click', () => this.showPrevious());
        document.getElementById('previewNext').addEventListener('click', () => this.showNext());

        // Закрытие по клику вне контента
        this.previewModal.addEventListener('click', (e) => {
            if (e.target === this.previewModal) {
                this.closePreview();
            }
        });

        // Закрытие по Escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.previewModal.classList.contains('active')) {
                this.closePreview();
            }
        });
    }

    // Initialize preview buttons for all files
    initPreviewButtons() {
        document.querySelectorAll('.file-item').forEach((row) => {
            const actionsCell = row.querySelector('.file-actions');
            const checkbox = row.querySelector('.file-checkbox');
            if (!actionsCell || !checkbox) return;

            const filename = checkbox.getAttribute('data-filename');
            if (!filename) return;

            const ext = filename.split('.').pop().toLowerCase();

            if (this.isPreviewableFile(ext)) {
                if (!actionsCell.querySelector('.btn-preview')) {
                    const previewBtn = document.createElement('button');
                    previewBtn.className = 'btn btn-preview';
                    previewBtn.title = 'Предпросмотр';
                    previewBtn.innerHTML = '<i class="fas fa-eye"></i>';
                    previewBtn.dataset.filename = filename;

                    previewBtn.addEventListener('click', (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        this.showPreview(filename);
                    });

                    if (actionsCell.firstChild) {
                        actionsCell.insertBefore(previewBtn, actionsCell.firstChild);
                    } else {
                        actionsCell.appendChild(previewBtn);
                    }
                }
            }
        });

        this.updatePreviewableFilesList();
    }

    // Добавляем новый метод для обработки inline обработчиков событий
    setupInlineEventHandlers() {
        document.querySelectorAll('.btn-preview').forEach(button => {
            if (button.hasAttribute('onclick')) {
                const filename = button.getAttribute('data-filename');
                if (filename) {
                    button.dataset.filename = filename;
                }
                button.removeAttribute('onclick');
            }

            button.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const filename = button.dataset.filename;
                if (filename) {
                    this.showPreview(filename);
                } else {
                    console.error('Кнопке предпросмотра не задан атрибут data-filename');
                }
            });
        });
    }

    // Update the list of previewable files
    updatePreviewableFilesList() {
        this.previewableFiles = Array.from(document.querySelectorAll('.btn-preview'))
            .map(btn => btn.dataset.filename)
            .filter(filename => filename);
    }

    // Check if file type is previewable
    isPreviewableFile(extension) {
        const ext = extension.toLowerCase();
        const previewableTypes = [
            'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp', 'ico', 'tiff', 'tif',
            'pdf',
            'txt', 'md', 'csv', 'tsv', 'json', 'xml', 'html', 'htm', 'css', 'js',
            'py', 'java', 'c', 'cpp', 'h', 'hpp', 'cs', 'php', 'rb', 'go', 'rs', 'ts',
            'jsx', 'tsx', 'sql', 'yml', 'yaml', 'ini', 'conf', 'config', 'sh', 'bat', 'ps1',
            'tex', 'bib', 'log', 'diff', 'patch'
        ];

        const excludedTypes = [
            'zip', 'rar', '7z', 'tar', 'gz', 'bz2'
        ];

        return previewableTypes.includes(ext) && !excludedTypes.includes(ext);
    }

    // Show preview for a specific file
    showPreview(filename) {
        this.currentIndex = this.previewableFiles.indexOf(filename);
        if (this.currentIndex === -1) {
            // Если файл не найден в списке предпросматриваемых, но кнопка есть,
            // возможно, это Office файл, для которого предпросмотр теперь отключен.
            // Показываем сообщение об ошибке.
            this.showPreviewError('Предпросмотр для этого типа файла недоступен. Вы можете скачать файл.');
            this.previewModal.classList.add('active'); // Показываем модальное окно с ошибкой
            // Устанавливаем имя файла в заголовке ошибки
            const errorFilenameElement = this.previewModal.querySelector('.preview-filename');
            if (errorFilenameElement) {
                errorFilenameElement.textContent = filename;
            }
            // Скрываем кнопки навигации
            const controls = this.previewModal.querySelector('.preview-controls');
            if (controls) {
                controls.style.display = 'none';
            }
            return;
        }

        this.updatePreviewContent();
        this.previewModal.classList.add('active');
    }

    // Update the preview content based on current index
    updatePreviewContent() {
        const filename = this.previewableFiles[this.currentIndex];
        // Если filename не определен (например, после удаления файла), выходим
        if (!filename) {
            this.closePreview();
            return;
        }

        this.previewContainer.innerHTML = '<div class="preview-loading"><i class="fas fa-spinner fa-spin"></i> Загрузка...</div>';
        this.previewFilename.textContent = filename;

        const ext = filename.split('.').pop().toLowerCase();
        const fileUrl = `/${this.linkId}/download/${encodeURIComponent(filename)}`;
        const absoluteFileUrl = new URL(fileUrl, window.location.origin).href;

        const imageTypes = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp', 'ico', 'tiff', 'tif'];
        const unsupportedPreviewTypes = [
            'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
            'doc', 'docx', 'docm', 'dot', 'dotx', 'dotm', 'rtf',
            'xls', 'xlsx', 'xlsm', 'xlt', 'xltx', 'xltm',
            'ppt', 'pptx', 'pptm', 'pot', 'potx', 'potm',
            'odt', 'ods', 'odp',
        ];
        const textTypes = [
            'txt', 'md', 'csv', 'tsv', 'json', 'xml', 'html', 'htm', 'css', 'js',
            'py', 'java', 'c', 'cpp', 'h', 'hpp', 'cs', 'php', 'rb', 'go', 'rs', 'ts',
            'jsx', 'tsx', 'sql', 'yml', 'yaml', 'ini', 'conf', 'config', 'sh', 'bat', 'ps1',
            'tex', 'bib', 'log', 'diff', 'patch'
        ];

        if (imageTypes.includes(ext)) {
            const img = document.createElement('img');
            img.className = 'preview-image';
            img.alt = filename;
            img.onload = () => {
                this.previewFilename.textContent = `${filename} (${img.naturalWidth}x${img.naturalHeight})`;
                const loadingDiv = this.previewContainer.querySelector('.preview-loading');
                if (loadingDiv) loadingDiv.style.display = 'none';
            };
            img.onerror = () => this.showPreviewError();
            img.src = fileUrl;
            this.previewContainer.innerHTML = '';
            this.previewContainer.appendChild(img);
        }
        else if (ext === 'pdf') {
            const embed = document.createElement('embed');
            embed.setAttribute('src', fileUrl);
            embed.setAttribute('type', 'application/pdf');
            embed.className = 'preview-pdf-embed';
            embed.onload = () => {
                const loadingDiv = this.previewContainer.querySelector('.preview-loading');
                if (loadingDiv) loadingDiv.remove();
            };
            embed.onerror = () => {
                this.showPreviewError('Не удалось загрузить предпросмотр PDF. Возможно, ваш браузер не поддерживает встроенный просмотр PDF.');
            };
            this.previewContainer.innerHTML = '';
            this.previewContainer.appendChild(embed);
        }
        else if (unsupportedPreviewTypes.includes(ext)) {
            this.showPreviewError('Предпросмотр для этого типа файла недоступен. Вы можете скачать файл.');
        }
        else if (textTypes.includes(ext)) {
            fetch(fileUrl)
                .then(response => {
                    if (!response.ok) throw new Error('Network response was not ok');
                    const contentType = response.headers.get('content-type');
                    let charset = 'utf-8';
                    if (contentType && contentType.includes('charset=')) {
                        charset = contentType.split('charset=')[1].split(';')[0];
                    }
                    return response.arrayBuffer().then(buffer => {
                        try {
                            return new TextDecoder(charset, { fatal: true }).decode(buffer);
                        } catch (e) {
                            try {
                                console.warn(`Failed to decode with ${charset}, trying windows-1251`);
                                return new TextDecoder('windows-1251', { fatal: true }).decode(buffer);
                            } catch (e2) {
                                console.warn('Failed to decode with windows-1251, trying default');
                                return new TextDecoder().decode(buffer);
                            }
                        }
                    });
                })
                .then(text => {
                    const pre = document.createElement('pre');
                    pre.className = 'preview-text';
                    pre.textContent = text;
                    this.previewContainer.innerHTML = '';
                    this.previewContainer.appendChild(pre);
                })
                .catch(error => {
                    console.error('Error fetching text file:', error);
                    this.showPreviewError();
                });
        }
        else {
            this.showPreviewError();
        }

        document.querySelector('.preview-controls').style.display =
            this.previewableFiles.length > 1 ? 'flex' : 'none';
    }

    // Show error state in preview
    showPreviewError(message = 'Не удалось показать предпросмотр для этого типа файлов') {
        let filename = this.previewableFiles[this.currentIndex];
        let downloadButtonHtml = '';
        if (filename) {
            const downloadUrl = `/${this.linkId}/download/${encodeURIComponent(filename)}?download=true`;
            downloadButtonHtml = `
                <a href="${downloadUrl}"
                   class="btn btn-primary" target="_blank" download>
                   <i class="fas fa-download"></i> Скачать файл
                </a>`;
        }

        this.previewContainer.innerHTML = `
            <div class="preview-error">
                <i class="fas fa-exclamation-triangle fa-3x"></i>
                <p>${message}</p>
                ${downloadButtonHtml}
            </div>
        `;
        this.previewFilename.textContent = filename || 'Ошибка предпросмотра';
    }

    // Show previous file
    showPrevious() {
        if (this.previewableFiles.length <= 1) return;

        this.currentIndex--;
        if (this.currentIndex < 0) {
            this.currentIndex = this.previewableFiles.length - 1;
        }
        this.updatePreviewContent();
    }

    // Show next file
    showNext() {
        if (this.previewableFiles.length <= 1) return;

        this.currentIndex++;
        if (this.currentIndex >= this.previewableFiles.length) {
            this.currentIndex = 0;
        }
        this.updatePreviewContent();
    }

    // Close preview modal
    closePreview() {
        this.previewModal.classList.remove('active');
        this.previewContainer.innerHTML = '';
        this.previewFilename.textContent = '';
    }
}

// Initialize the preview functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    if (typeof linkId !== 'undefined') {
        window.previewManager = new FilePreviewManager(linkId);

        window.previewManager.initPreviewButtons();
    }
});

// Добавляем глобальную функцию для вызова из HTML (если где-то используется)
function showPreview(filename) {
    if (window.previewManager) {
        window.previewManager.showPreview(filename);
    } else {
        console.error('Preview manager is not initialized');
    }
}
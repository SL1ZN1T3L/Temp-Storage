document.addEventListener('DOMContentLoaded', function() {
    const uploadForm = document.getElementById('upload-form');
    const fileInput = document.getElementById('file-input');

    uploadForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const files = fileInput.files;
        if (files.length === 0) {
            alert('Пожалуйста, выберите файлы для загрузки');
            return;
        }

        const formData = new FormData();
        for (let i = 0; i < files.length; i++) {
            formData.append('file', files[i]);
        }

        try {
            const response = await fetch(`/${window.linkId}/upload`, {
                method: 'POST',
                body: formData
            });

            const result = await response.json();
            
            if (response.ok) {
                alert('Файлы успешно загружены');
                location.reload();
            } else {
                alert(result.error || 'Ошибка при загрузке файлов');
            }
        } catch (error) {
            console.error('Ошибка:', error);
            alert('Произошла ошибка при загрузке файлов');
        }
    });
});

async function deleteFile(filename) {
    if (!confirm('Вы уверены, что хотите удалить этот файл?')) {
        return;
    }

    try {
        const response = await fetch(`/${window.linkId}/delete/${filename}`, {
            method: 'POST'
        });

        const result = await response.json();
        
        if (response.ok) {
            alert('Файл успешно удален');
            location.reload();
        } else {
            alert(result.error || 'Ошибка при удалении файла');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('Произошла ошибка при удалении файла');
    }
} 
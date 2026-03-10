export const MAX_ADMIN_IMAGE_SIZE_BYTES = 5 * 1024 * 1024;

const ALLOWED_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);
const ALLOWED_IMAGE_EXTENSIONS = /\.(jpg|jpeg|png|webp)$/i;

function randomId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

export function validateImageFiles(files = []) {
  const validFiles = [];
  const errors = [];

  files.forEach((file) => {
    const hasValidType = ALLOWED_IMAGE_TYPES.has(file.type) || ALLOWED_IMAGE_EXTENSIONS.test(file.name || '');
    if (!hasValidType) {
      errors.push(`${file.name}: only JPG, JPEG, PNG, or WEBP files are allowed.`);
      return;
    }

    if (file.size > MAX_ADMIN_IMAGE_SIZE_BYTES) {
      errors.push(`${file.name}: file size must be 5 MB or less.`);
      return;
    }

    validFiles.push(file);
  });

  return { validFiles, errors };
}

export function createPendingImageAsset(file) {
  return {
    id: randomId('pending'),
    url: URL.createObjectURL(file),
    name: file.name,
    file,
    pending: true
  };
}

export function createSavedImageAsset(url) {
  const cleanUrl = url || '';
  const filename = cleanUrl.split('/').pop()?.split('?')[0] || 'uploaded-image';

  return {
    id: randomId('saved'),
    url: cleanUrl,
    name: decodeURIComponent(filename),
    file: null,
    pending: false
  };
}

export function toSavedImageAssets(urls = []) {
  return urls.filter(Boolean).map(createSavedImageAsset);
}

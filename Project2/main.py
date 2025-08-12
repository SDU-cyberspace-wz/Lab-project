import cv2
import numpy as np
import pywt

def watermark_create(image_path, watermark_path, out_path, alpha=0.05):
    image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE).astype(np.float32)
    watermark = cv2.imread(watermark_path, cv2.IMREAD_GRAYSCALE).astype(np.float32)
    wm_resized = cv2.resize(watermark, (image.shape[1] // 2, image.shape[0] // 2))

    coeffs = pywt.dwt2(image, 'haar')
    LL, (LH, HL, HH) = coeffs
    LH_wm = LH + alpha * wm_resized
    coeffs_wm = (LL, (LH_wm, HL, HH))
    watermarked_image = pywt.idwt2(coeffs_wm, 'haar')
    cv2.imwrite(out_path, np.uint8(np.clip(watermarked_image, 0, 255)))

fa
def extract_watermark(watermarked_path, original_path, watermark_shape, alpha=0.05):
    watermarked = cv2.imread(watermarked_path, cv2.IMREAD_GRAYSCALE).astype(np.float32)
    original = cv2.imread(original_path, cv2.IMREAD_GRAYSCALE).astype(np.float32)

    coeffs_wm = pywt.dwt2(watermarked, 'haar')
    LL_wm, (LH_wm, HL_wm, HH_wm) = coeffs_wm

    coeffs_orig = pywt.dwt2(original, 'haar')
    LL_o, (LH_o, HL_o, HH_o) = coeffs_orig

    # 提取水印
    wm_extracted = (LH_wm - LH_o) / alpha
    wm_extracted = cv2.resize(wm_extracted, (watermark_shape[1], watermark_shape[0]))

    return np.uint8(np.clip(wm_extracted, 0, 255))


def flip(image_path):
    image = cv2.imread(image_path, cv2.IMREAD_COLOR)
    flipped_image = cv2.flip(image, 1)
    cv2.imwrite('flipped_output.png',flipped_image)


def shift(image_path):
    image = cv2.imread(image_path, cv2.IMREAD_COLOR)
    rows, cols = image.shape[:2]
    M = np.float32([[1, 0, 30],  # x 方向平移 30 像素
                    [0, 1, 50]])  # y 方向平移 50 像素
    shifted_image = cv2.warpAffine(image, M, (cols, rows))
    cv2.imwrite('shifted_output.png', shifted_image)

def crop(image_path):
    image = cv2.imread(image_path, cv2.IMREAD_COLOR)
    cropped_image = image[50:200, 100:300]
    cropped_image = cv2.resize(cropped_image,(image.shape[1],image.shape[0]))
    cv2.imwrite('cropped_output.png', cropped_image)

def contrast(image_path):
    image = cv2.imread(image_path, cv2.IMREAD_COLOR)
    alpha = 1.5
    beta = 0
    contrast_image = cv2.convertScaleAbs(image, alpha, beta)
    cv2.imwrite('contrast_output.png', contrast_image)


if __name__ == "__main__":
    alpha = 0.25
    watermark_create('reference.png', 'watermark.png', 'output.png',alpha)

    extracted = extract_watermark('output.png', 'reference.png', (120,418),alpha)
    cv2.imwrite("results/exteacted.png", extracted)
    flip('output.png')
    shift('output.png')
    crop('output.png')
    contrast('output.png')

    extracted = extract_watermark('flipped_output.png', 'reference.png', (120,418),alpha)
    cv2.imwrite("results/flipped_exteacted.png", extracted)

    extracted = extract_watermark('shifted_output.png', 'reference.png', (120,418),alpha)
    cv2.imwrite("results/shifted_exteacted.png", extracted)

    extracted = extract_watermark('cropped_output.png', 'reference.png', (120,418),alpha)
    cv2.imwrite("results/cropped_exteacted.png", extracted)

    extracted = extract_watermark('contrast_output.png', 'reference.png', (120,418),alpha)
    cv2.imwrite("results/contrast_exteacted.png", extracted)
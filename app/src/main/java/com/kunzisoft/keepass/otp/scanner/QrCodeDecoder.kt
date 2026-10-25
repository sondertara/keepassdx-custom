/*
 * Copyright 2026 Jeremy Jamet / Kunzisoft.
 *
 * This file is part of KeePassDX.
 *
 *  KeePassDX is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  KeePassDX is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with KeePassDX.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package com.kunzisoft.keepass.otp.scanner

import android.graphics.Bitmap
import android.util.Log
import androidx.camera.core.ImageProxy
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import java.nio.ByteBuffer
import java.util.EnumMap

/**
 * Pure local offline QR Code decoder utility using ZXing.
 * Zero network dependencies and GC-friendly.
 */
object QrCodeDecoder {

    private const val TAG = "QrCodeDecoder"

    private val readerHints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
        put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
        put(DecodeHintType.CHARACTER_SET, "UTF-8")
        put(DecodeHintType.TRY_HARDER, java.lang.Boolean.TRUE)
    }

    /**
     * Decode a static Bitmap (e.g. from gallery, screenshot, or file picker).
     * @param bitmap Input bitmap to decode.
     * @param recycle Whether to recycle the bitmap after decoding.
     * @return Decoded QR string or null if not found/error.
     */
    fun decodeBitmap(bitmap: Bitmap, recycle: Boolean = true): String? {
        try {
            val width = bitmap.width
            val height = bitmap.height
            val pixels = IntArray(width * height)
            bitmap.getPixels(pixels, 0, width, 0, 0, width, height)

            val source = RGBLuminanceSource(width, height, pixels)
            val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
            val reader = MultiFormatReader()

            try {
                val result = reader.decode(binaryBitmap, readerHints)
                return result.text
            } catch (e: Exception) {
                // Try fallback with GlobalHistogramBinarizer for unevenly lit or low contrast screenshots
                return try {
                    val fallbackBitmap = BinaryBitmap(GlobalHistogramBinarizer(source))
                    val fallbackResult = reader.decode(fallbackBitmap, readerHints)
                    fallbackResult.text
                } catch (e2: Exception) {
                    null
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error decoding bitmap", e)
            return null
        } finally {
            if (recycle && !bitmap.isRecycled) {
                bitmap.recycle()
            }
        }
    }

    /**
     * Decode a live camera frame from CameraX [ImageProxy] in YUV_420_888 format.
     * Fast luminance plane extraction without RGB conversion overhead.
     */
    fun decodeImageProxy(image: ImageProxy): String? {
        val plane = image.planes[0]
        val buffer: ByteBuffer = plane.buffer
        val bytes = ByteArray(buffer.remaining())
        buffer.get(bytes)

        val width = image.width
        val height = image.height

        val source = PlanarYUVLuminanceSource(
            bytes,
            width,
            height,
            0,
            0,
            width,
            height,
            false
        )
        val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
        val reader = MultiFormatReader()

        return try {
            val result = reader.decode(binaryBitmap, readerHints)
            result.text
        } catch (e: Exception) {
            null
        }
    }
}

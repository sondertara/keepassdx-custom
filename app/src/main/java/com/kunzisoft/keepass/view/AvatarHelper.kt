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
package com.kunzisoft.keepass.view

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.util.LruCache
import java.util.Locale
import kotlin.math.abs

/**
 * Modern 2FAS-style Squircle Avatar and brand badge generator.
 */
object AvatarHelper {

    private val cache = LruCache<String, Drawable>(120)

    private val PALETTE = intArrayOf(
        Color.parseColor("#2563EB"), // Royal Blue
        Color.parseColor("#7C3AED"), // Violet
        Color.parseColor("#0D9488"), // Teal
        Color.parseColor("#D97706"), // Amber
        Color.parseColor("#E11D48"), // Rose
        Color.parseColor("#059669"), // Emerald
        Color.parseColor("#4F46E5"), // Indigo
        Color.parseColor("#DB2777"), // Pink
        Color.parseColor("#0284C7"), // Sky
        Color.parseColor("#EA580C")  // Orange
    )

    fun getAvatarDrawable(context: Context, rawTitle: String): Drawable {
        val title = rawTitle.trim()
        val cacheKey = title
        cache.get(cacheKey)?.let { return it }

        val sizeDp = 44
        val cornerRadiusDp = 12
        val density = context.resources.displayMetrics.density
        val sizePx = (sizeDp * density).toInt()
        val cornerPx = cornerRadiusDp * density

        val bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)

        // 1. Background color selection
        val colorIndex = abs(title.hashCode()) % PALETTE.size
        val bgColor = PALETTE[colorIndex]

        val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = bgColor
            style = Paint.Style.FILL
        }
        val rect = RectF(0f, 0f, sizePx.toFloat(), sizePx.toFloat())
        canvas.drawRoundRect(rect, cornerPx, cornerPx, bgPaint)

        // 2. Text badge extraction
        val badgeText = extractBadgeText(title)

        // 3. Draw text
        val isChinese = badgeText.any { it.code in 0x4E00..0x9FFF }
        val textSizeSp = if (isChinese) 15f else if (badgeText.length > 2) 14f else 17f
        val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.WHITE
            textSize = textSizeSp * context.resources.displayMetrics.scaledDensity
            typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
            textAlign = Paint.Align.CENTER
        }

        val textBounds = Rect()
        textPaint.getTextBounds(badgeText, 0, badgeText.length, textBounds)
        val textY = (sizePx / 2f) + (textBounds.height() / 2f) - textBounds.bottom
        canvas.drawText(badgeText, sizePx / 2f, textY, textPaint)

        val drawable = BitmapDrawable(context.resources, bitmap)
        cache.put(cacheKey, drawable)
        return drawable
    }

    private fun extractBadgeText(title: String): String {
        if (title.isBlank()) return "??"

        // Check if domain
        var clean = title.lowercase(Locale.ROOT)
            .removePrefix("https://")
            .removePrefix("http://")
            .removePrefix("www.")
            .removePrefix("account.")
            .removePrefix("login.")
            .removePrefix("id.")
            .removePrefix("auth.")

        // If domain format, take main brand part
        if (clean.contains(".")) {
            val domainParts = clean.split(".")
            clean = domainParts.firstOrNull { it.length > 2 } ?: domainParts[0]
        }

        // Chinese character handling
        val firstChar = title.first()
        if (firstChar.code in 0x4E00..0x9FFF) {
            return title.take(2)
        }

        // Word initials handling
        val words = title.split("\\s+|-|_|\\.".toRegex()).filter { it.isNotBlank() }
        return when {
            words.size >= 2 -> {
                val w1 = words[0].firstOrNull()?.uppercaseChar() ?: ' '
                val w2 = words[1].firstOrNull()?.uppercaseChar() ?: ' '
                "$w1$w2".trim()
            }
            clean.length >= 2 -> {
                clean.take(2).uppercase(Locale.ROOT)
            }
            else -> {
                clean.uppercase(Locale.ROOT)
            }
        }
    }
}

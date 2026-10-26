package com.kunzisoft.keepass.adapters

import android.content.Context
import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.ImageView
import android.widget.TextView
import com.kunzisoft.keepass.R
import com.kunzisoft.keepass.database.element.template.Template
import com.kunzisoft.keepass.database.element.template.TemplateField
import com.kunzisoft.keepass.database.helper.getLocalizedName
import com.kunzisoft.keepass.icons.IconDrawableFactory


class TemplatesSelectorAdapter(
    private val context: Context,
    private var templates: List<Template>): BaseAdapter() {

    var iconDrawableFactory: IconDrawableFactory? = null
    private val inflater: LayoutInflater = LayoutInflater.from(context)
    private var mTextColor = Color.BLACK

    init {
        val taTextColor = context.theme.obtainStyledAttributes(intArrayOf(android.R.attr.textColor))
        mTextColor = taTextColor.getColor(0, Color.BLACK)
        taTextColor.recycle()
    }

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        return bindTemplateView(position, convertView, parent, isDropDown = false)
    }

    override fun getDropDownView(position: Int, convertView: View?, parent: ViewGroup): View {
        return bindTemplateView(position, convertView, parent, isDropDown = true)
    }

    private fun bindTemplateView(
        position: Int,
        convertView: View?,
        parent: ViewGroup,
        isDropDown: Boolean
    ): View {
        val template: Template = getItem(position)

        val holder: TemplateSelectorViewHolder
        var templateView = convertView
        if (templateView == null) {
            holder = TemplateSelectorViewHolder()
            templateView = inflater
                .cloneInContext(context)
                .inflate(R.layout.item_template, parent, false)
            holder.background = templateView?.findViewById(R.id.template_background)
            holder.icon = templateView?.findViewById(R.id.template_image)
            holder.name = templateView?.findViewById(R.id.template_name)
            holder.chevron = templateView?.findViewById(R.id.template_chevron)
            templateView?.tag = holder
        } else {
            holder = templateView.tag as TemplateSelectorViewHolder
        }

        if (isDropDown) {
            holder.background?.setBackgroundColor(template.backgroundColor ?: Color.TRANSPARENT)
            holder.chevron?.visibility = View.GONE
            val density = context.resources.displayMetrics.density
            val hPad = (16 * density).toInt()
            val vPad = (10 * density).toInt()
            holder.background?.setPadding(hPad, vPad, hPad, vPad)
            holder.background?.minimumHeight = (44 * density).toInt()
        } else {
            holder.background?.setBackgroundResource(R.drawable.bg_template_selector_pill)
            holder.chevron?.visibility = View.VISIBLE
            val density = context.resources.displayMetrics.density
            val startPad = (14 * density).toInt()
            val endPad = (10 * density).toInt()
            holder.background?.setPadding(startPad, 0, endPad, 0)
            holder.background?.minimumHeight = (38 * density).toInt()
        }

        val textColor = template.foregroundColor ?: mTextColor
        holder.icon?.let { icon ->
            iconDrawableFactory?.assignDatabaseIcon(icon, template.icon, textColor)
        }
        holder.name?.apply {
            setTextColor(textColor)
            text = TemplateField.getLocalizedName(context, template.title)
        }

        return templateView!!
    }

    override fun getCount(): Int {
        return templates.size
    }

    override fun getItem(position: Int): Template {
        return templates[position]
    }

    override fun getItemId(position: Int): Long {
        return position.toLong()
    }

    inner class TemplateSelectorViewHolder {
        var background: View? = null
        var icon: ImageView? = null
        var name: TextView? = null
        var chevron: ImageView? = null
    }
}

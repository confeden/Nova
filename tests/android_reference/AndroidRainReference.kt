package com.example.nova
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import java.io.File
fun main(args:Array<String>) {
 val w=args[0].toInt();val h=args[1].toInt();val variant=args[2].toInt();val time=args[3].toDouble();val alpha=args[4].toFloat()
 val bitmap=Bitmap(w,h)
 NovaMatrixRain.shared(w,h,variant).draw(Canvas(bitmap),Paint(Paint.ANTI_ALIAS_FLAG),time,alpha)
 File(args[5]).writeText(bitmap.events.joinToString(",","[","]"))
}

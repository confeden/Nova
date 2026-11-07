package com.example.nova
import android.graphics.Bitmap
import java.io.File
object NovaAppearance {
 enum class Texture(val key:String) {NONE("none"),BASALT("basalt"),MARBLE("marble"),WOOD("wood"),SAND("sand"),GRASS("grass"),CRACKS("cracks"),WATER("water"),SMOKE("smoke"),STARFIELD("starfield"),SLIME("slime"),SHARDS("shards"),SPLATTER("splatter"),LIGHTNING("lightning"),SNOW("snow"),FRACTAL("fractal"),MATRIX("matrix")}
}
fun main(args:Array<String>) {
 val texture=NovaAppearance.Texture.entries.first{it.key==args[0]};val w=args[1].toInt();val h=args[2].toInt();val variant=args[3].toInt()
 val bitmap=NovaTexturePatterns.render(texture,w,h,variant)?:Bitmap(w,h)
 val bytes=ByteArray(w*h){(bitmap.pixels[it] ushr 24).toByte()}
 File(args[4]+".pgm").writeBytes("P5\n$w $h\n255\n".toByteArray()+bytes)
 // Sheet.drawing's outer save/scale/restore is supplied by the native surface, so omit only that wrapper.
 val events=bitmap.events.toMutableList()
 if(events.isNotEmpty()) {require(events[0].contains("\"save\""));require(events[1].contains("\"scale\""));require(events.last().contains("\"restore\""));events.removeAt(events.lastIndex);events.removeAt(1);events.removeAt(0)}
 File(args[4]+".json").writeText(events.joinToString(",","[","]"))
}

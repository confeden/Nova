package android.graphics
// Verification sink: keep Android generator code unchanged; capture alpha fields and drawing commands.
class Bitmap(val width:Int,val height:Int) {
 enum class Config { ARGB_8888, ALPHA_8 }
 var glyph:String?=null
 val pixels=IntArray(width*height)
 val events=ArrayList<String>()
 fun setPixels(p:IntArray,offset:Int,stride:Int,x:Int,y:Int,w:Int,h:Int) {for(row in 0 until h)for(col in 0 until w)pixels[(y+row)*width+x+col]=p[offset+row*stride+col]}
 companion object {fun createBitmap(w:Int,h:Int,c:Config)=Bitmap(w,h)}
}
object Color {const val WHITE:Int=-1;fun argb(a:Int,r:Int,g:Int,b:Int):Int=(a shl 24) or (r shl 16) or (g shl 8) or b}
open class Shader {enum class TileMode {CLAMP};var stops:List<Pair<Float,Int>> = emptyList()}
class RadialGradient:Shader {
 constructor(x:Float,y:Float,r:Float,a:Int,b:Int,mode:TileMode){stops=listOf(0f to (a ushr 24),1f to (b ushr 24))}
 constructor(x:Float,y:Float,r:Float,colors:IntArray,positions:FloatArray?,mode:TileMode){stops=colors.indices.map{(positions?.get(it)?:it.toFloat()/(colors.size-1)) to (colors[it] ushr 24)}}
}
object PorterDuff {enum class Mode {DST_OUT}}
class PorterDuffXfermode(val mode:PorterDuff.Mode)
class Typeface {companion object {val MONOSPACE=Typeface()}}
class Paint(flags:Int=0) {
 enum class Style {FILL,STROKE};enum class Cap {BUTT,ROUND};enum class Join {MITER,ROUND};enum class Align {CENTER}
 var color=Color.WHITE;var alpha=255;var style=Style.FILL;var strokeWidth=0f;var strokeCap=Cap.BUTT;var strokeJoin=Join.MITER
 var shader:Shader?=null;var xfermode:PorterDuffXfermode?=null;var typeface:Typeface?=null;var textAlign=Align.CENTER;var textSize=0f;var isFakeBoldText=false
 fun hasGlyph(s:String)=true
 fun record():String {
  val stroke=style==Style.STROKE
  val gradient=shader?.stops?.joinToString(",","[","]"){"[${it.first},${it.second}]"}?:"null"
  return "{\"alpha\":${alpha.coerceIn(0,255)},\"width\":${if(stroke)strokeWidth else 0f},\"stroke\":$stroke,\"round_cap\":${stroke&&strokeCap==Cap.ROUND},\"round_join\":${stroke&&strokeJoin==Join.ROUND},\"erase\":${xfermode!=null},\"gradient\":$gradient}"
 }
 companion object {const val ANTI_ALIAS_FLAG=1;const val FILTER_BITMAP_FLAG=2}
}
class Matrix {
 var angle=0f;var x=0f;var y=0f
 fun reset(){angle=0f;x=0f;y=0f}
 fun setRotate(degrees:Float,px:Float,py:Float){require(px==0f&&py==0f);angle=degrees}
 fun postTranslate(dx:Float,dy:Float){x+=dx;y+=dy}
}
class Path {
 enum class Direction {CW}
 val ops=ArrayList<Float>()
 fun reset(){ops.clear()}
 fun moveTo(x:Float,y:Float){ops.addAll(listOf(0f,x,y))}
 fun lineTo(x:Float,y:Float){ops.addAll(listOf(1f,x,y))}
 fun quadTo(x:Float,y:Float,x1:Float,y1:Float){ops.addAll(listOf(2f,x,y,x1,y1))}
 fun close(){ops.add(4f)}
 fun addOval(l:Float,t:Float,r:Float,b:Float,d:Direction){ops.addAll(listOf(5f,(l+r)*0.5f,(t+b)*0.5f,(r-l)*0.5f,(b-t)*0.5f,0f))}
 fun addPath(p:Path,m:Matrix){require(p.ops.size==6&&p.ops[0]==5f);ops.addAll(listOf(5f,p.ops[1]+m.x,p.ops[2]+m.y,p.ops[3],p.ops[4],p.ops[5]+m.angle))}
}
class Canvas(val bitmap:Bitmap) {
 fun record(kind:String,values:List<Float> = emptyList(),paint:Paint?=null,text:String?=null){bitmap.events.add("{\"kind\":\"$kind\",\"values\":${values.joinToString(",","[","]")},\"paint\":${paint?.record()?:"null"},\"text\":${text?.let{"\"$it\""}?:"null"}}")}
 fun save(){record("save")};fun restore(){record("restore")};fun scale(x:Float,y:Float){record("scale",listOf(x,y))};fun translate(x:Float,y:Float){record("translate",listOf(x,y))};fun rotate(a:Float){record("rotate",listOf(a))}
 fun drawPath(p:Path,paint:Paint){record("path",p.ops,paint)}
 fun drawCircle(x:Float,y:Float,r:Float,paint:Paint){record("path",listOf(6f,x,y,r),paint)}
 fun drawLine(x:Float,y:Float,x1:Float,y1:Float,paint:Paint){record("path",listOf(0f,x,y,1f,x1,y1),paint)}
 fun drawPoints(p:FloatArray,offset:Int,count:Int,paint:Paint){val style=paint.style;paint.style=Paint.Style.FILL;for(i in offset until offset+count step 2)drawCircle(p[i],p[i+1],paint.strokeWidth*0.5f,paint);paint.style=style}
 fun drawText(s:String,x:Float,y:Float,paint:Paint){bitmap.glyph=s;record("text",listOf(x,y,paint.textSize,if(paint.isFakeBoldText)1f else 0f),paint,s)}
 fun drawBitmap(b:Bitmap,x:Float,y:Float,paint:Paint){record("bitmap",listOf(x,y,b.width.toFloat(),b.height.toFloat()),paint,b.glyph)}
}

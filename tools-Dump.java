import java.lang.reflect.*;

public class Dump {
    static String arr(Object v) {
        Class<?> comp = v.getClass().getComponentType();
        int n = Array.getLength(v);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(',');
            if (comp == char.class) sb.append((int) Array.getChar(v, i));
            else if (comp == short.class) sb.append(Array.getShort(v, i));
            else if (comp == int.class) sb.append(Array.getInt(v, i));
            else if (comp == byte.class) sb.append(Array.getByte(v, i));
            else if (comp == float.class) sb.append(Array.getFloat(v, i));
            else if (comp == long.class) sb.append(Array.getLong(v, i));
            else sb.append(Array.get(v, i));
        }
        return n + ":" + sb;
    }

    public static void main(String[] a) throws Exception {
        Class<?> c = Class.forName("com.avocent.kvm.a.a.d");
        // Instantiate to run the constructor (may populate more tables).
        try { c.getDeclaredConstructor().newInstance(); } catch (Throwable t) {}
        for (Field f : c.getDeclaredFields()) {
            if (!Modifier.isStatic(f.getModifiers())) continue;
            f.setAccessible(true);
            Object v;
            try { v = f.get(null); } catch (Throwable t) { continue; }
            if (v == null || !v.getClass().isArray()) continue;
            Class<?> comp = v.getClass().getComponentType();
            if (comp.isArray() || !comp.isPrimitive()) continue; // skip 2D / object arrays
            System.out.println(f.getName() + " " + comp.getName() + " " + arr(v));
        }
    }
}

internal static class Program
{
    private static void Main()
    {
        Console.WriteLine(Calculate(3));
        Console.WriteLine(ProtectedCalculation(3));
    }

    private static int Calculate(int input)
    {
        var value = input + 1; // VISION_REWIND_TARGET
        value *= 2;
        Console.WriteLine($"guard:{value}"); // VISION_GUARD_BREAKPOINT
        return value;
    }

    private static int ProtectedCalculation(int input)
    {
        var value = input; // VISION_EH_OUTSIDE_TARGET
        try
        {
            value += 1;
            value *= 2; // VISION_EH_GUARD
        }
        finally
        {
            value += 0;
        }

        return value;
    }
}

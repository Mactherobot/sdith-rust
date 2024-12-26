import numpy as np
import matplotlib.pyplot as plt


def generate_polynomials(point1, point2, secrets):
    """
    Creates three different degree-3 polynomials passing through two given points.

    Args:
        point1 (tuple): The first point (x1, y1).
        point2 (tuple): The second point (x2, y2).
        secrets (list): A list of y-values for the secrets.

    Returns:
        list: A list of three numpy.poly1d objects representing the polynomials.
    """
    x1, y1 = point1
    x2, y2 = point2

    polynomials = []

    for y0 in secrets:
        p = np.polyfit([0, x1, x2], [y0, y1, y2], deg=3)
        polynomials.append(np.poly1d(p))

    # Plot the polynomials and points
    x_vals = np.linspace(min(x1, x2) - 1, max(x1, x2) + 2, 500)
    plt.figure(figsize=(10, 6))

    for i, poly in enumerate(polynomials):
        y_vals = poly(x_vals)
        plt.plot(
            x_vals,
            y_vals,
            color="black" if i == 2 else "darkgray",
            linewidth=0.8,
            linestyle="--" if i != 2 else "-",
        )
        plt.scatter(
            0, poly(0), marker="x", color="black" if i == 2 else "darkgray"
        )  # Intersection with y-axis

    # Plot the two given points
    plt.scatter([x1, x2], [y1, y2], color="black", zorder=5, marker="x")

    # Customize plot
    plt.axhline(0, color="black", linewidth=0.8)
    plt.axvline(0, color="black", linewidth=0.8)
    plt.xticks([])  # Remove x-axis tick labels
    plt.yticks([])  # Remove y-axis tick labels
    plt.
    plt.grid(alpha=0.4)
    plt.show()

    return polynomials


# Example usage
point1 = (1, 2)
point2 = (3, 5)

polys = generate_polynomials(point1, point2, [1, 2, 3])

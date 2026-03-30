import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, VueWrapper } from "@vue/test-utils";
import { ref } from "vue";

// Mock @floating-ui/vue — jsdom cannot measure DOM geometry
vi.mock("@floating-ui/vue", () => ({
  useFloating: () => ({
    floatingStyles: ref({ position: "fixed", top: "0px", left: "200px" }),
    placement: ref("right"),
    middlewareData: ref({ arrow: { x: undefined, y: 4 } }),
  }),
  flip: () => ({}),
  shift: () => ({}),
  offset: () => ({}),
  arrow: () => ({}),
  autoUpdate: vi.fn(),
}));

// Stub Teleport so the floating panel renders inline during tests
const globalConfig = {
  stubs: { Teleport: true },
};

describe("InfoPopup", () => {
  let InfoPopup: any;
  let wrappers: VueWrapper[];

  beforeEach(async () => {
    vi.resetModules();
    const mod = await import("./InfoPopup.vue");
    InfoPopup = mod.default;
    wrappers = [];
  });

  afterEach(() => {
    wrappers.forEach((w) => w.unmount());
    wrappers = [];
  });

  function createWrapper(slots: Record<string, string> = {}) {
    const w = mount(InfoPopup, {
      slots: {
        trigger: "<button data-trigger>?</button>",
        default: "<span>details</span>",
        ...slots,
      },
      global: globalConfig,
    });
    wrappers.push(w);
    return w;
  }

  it("is closed by default", () => {
    const wrapper = createWrapper();
    expect(wrapper.find("[data-floating]").exists()).toBe(false);
  });

  it("opens when trigger is clicked", async () => {
    const wrapper = createWrapper();
    await wrapper.find("[data-infopopup-trigger]").trigger("click");
    expect(wrapper.find("[data-floating]").exists()).toBe(true);
  });

  it("closes when trigger is clicked again", async () => {
    const wrapper = createWrapper();
    await wrapper.find("[data-infopopup-trigger]").trigger("click");
    await wrapper.find("[data-infopopup-trigger]").trigger("click");
    expect(wrapper.find("[data-floating]").exists()).toBe(false);
  });

  it("shows on pointerenter (mouse) and hides on pointerleave", async () => {
    const wrapper = createWrapper();
    await wrapper
      .find("[data-infopopup-trigger]")
      .trigger("pointerenter", { pointerType: "mouse" });
    expect(wrapper.find("[data-floating]").exists()).toBe(true);
    await wrapper
      .find("[data-infopopup-trigger]")
      .trigger("pointerleave", { pointerType: "mouse" });
    expect(wrapper.find("[data-floating]").exists()).toBe(false);
  });

  it("renders default slot content when open", async () => {
    const wrapper = createWrapper({
      default: '<span class="content">hello</span>',
    });
    await wrapper.find("[data-infopopup-trigger]").trigger("click");
    expect(wrapper.find(".content").text()).toBe("hello");
  });

  it("applies floatingStyles to the floating panel", async () => {
    const wrapper = createWrapper();
    await wrapper.find("[data-infopopup-trigger]").trigger("click");
    const panel = wrapper.find("[data-floating]");
    expect(panel.attributes("style")).toContain("left: 200px");
  });

  it("singleton: opening one closes another", async () => {
    const w1 = createWrapper();
    const w2 = createWrapper();

    await w1.find("[data-infopopup-trigger]").trigger("click");
    expect(w1.find("[data-floating]").exists()).toBe(true);

    await w2.find("[data-infopopup-trigger]").trigger("click");
    expect(w2.find("[data-floating]").exists()).toBe(true);
    expect(w1.find("[data-floating]").exists()).toBe(false);
  });

  it("removes global click listener when last instance unmounts", () => {
    const removeSpy = vi.spyOn(document, "removeEventListener");
    const w1 = createWrapper();
    const w2 = createWrapper();

    // Remove from tracked list so afterEach doesn't double-unmount
    wrappers = [];

    w1.unmount();
    // Still one instance mounted — listener should stay
    expect(removeSpy).not.toHaveBeenCalledWith(
      "click",
      expect.any(Function),
      true
    );

    w2.unmount();
    // Last instance gone — listener should be removed
    expect(removeSpy).toHaveBeenCalledWith(
      "click",
      expect.any(Function),
      true
    );
    removeSpy.mockRestore();
  });

  it("cleans up singleton state when open popup is destroyed", async () => {
    const w1 = createWrapper();
    const w2 = createWrapper();

    await w1.find("[data-infopopup-trigger]").trigger("click");
    expect(w1.find("[data-floating]").exists()).toBe(true);

    // Remove w1 from tracked list and unmount while open
    wrappers = wrappers.filter((w) => w !== w1);
    w1.unmount();

    // w2 should be able to open independently (no stale singleton reference)
    await w2.find("[data-infopopup-trigger]").trigger("click");
    expect(w2.find("[data-floating]").exists()).toBe(true);
  });
});
